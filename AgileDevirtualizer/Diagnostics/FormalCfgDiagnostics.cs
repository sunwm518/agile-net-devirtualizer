using System.Text;
using AgileDevirtualizer.Analysis;
using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;

namespace AgileDevirtualizer.Diagnostics;

/// <summary>Text/DOT projection of the formal observational IR and CFG.</summary>
internal static class FormalCfgDiagnostics
{
    public static void Write(
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted,
        Action<string, string> write,
        IReadOnlyList<LegacyStateSnapshot>? legacySnapshots = null)
    {
        try
        {
            var graph = ControlFlowGraphBuilder.Build(decoded, lifted);
            WriteSemanticIr(graph, write);
            WriteBlocks(graph, decoded, write);
            WriteDot(graph, write);
            WriteValidation(graph, write);
            var analysis = WorklistAnalyzer.Analyze(graph);
            WriteWorklist(analysis, write);
            var ssa = WriteSsa(target, graph, analysis, write);
            WriteExceptionEntries(target, ssa, write);
            var sccp = WriteSccp(ssa, write);
            var deadCode = WriteDeadCode(sccp, write);
            WriteControlFlowSimplification(deadCode, write);
            WriteRegionPhiCopyLegality(deadCode, write);
            WriteExceptionContinuations(ssa, write);
            if (legacySnapshots is not null)
                WriteLegacyComparison(
                    LegacyStateComparer.Compare(graph, analysis, legacySnapshots), write);
        }
        catch (Exception ex)
        {
            write("10-cfg-validation.txt", "Formal CFG diagnostics failed: " + ex + Environment.NewLine);
        }
    }

    private static void WriteExceptionContinuations(
        SsaGraph ssa,
        Action<string, string> write)
    {
        var model = ExceptionContinuationModelBuilder.Build(ssa);
        var verification = ExceptionContinuationModelVerifier.Verify(model);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Leaves: {model.Leaves.Count}")
            .AppendLine($"Rethrows: {model.Rethrows.Count}")
            .AppendLine($"Endfinallys: {model.EndFinallys.Count}")
            .AppendLine($"Endfilters: {model.EndFilters.Count}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var leave in model.Leaves)
            text.AppendLine($"L{leave.Id} B{leave.Edge.SourceBlockId}->"
                + $"B{leave.FinalTargetBlockId} finally=[{string.Join(",", leave.FinallyRegionIds)}] "
                + leave.Transition.Kind);
        foreach (var rethrow in model.Rethrows)
            text.AppendLine($"B{rethrow.SourceBlockId} rethrow catch=EH{rethrow.ActiveCatchRegionId}");
        foreach (var endFinally in model.EndFinallys)
            text.AppendLine($"B{endFinally.SourceBlockId} endfinally EH{endFinally.HandlerRegionId} "
                + $"{endFinally.HandlerKind} leaves=[{string.Join(",", endFinally.ResumableLeaveIds)}]");
        foreach (var endFilter in model.EndFilters)
            text.AppendLine($"B{endFilter.SourceBlockId} endfilter EH{endFilter.FilterRegionId} "
                + $"accept=B{endFilter.AcceptedHandlerBlockId} reject=exception-search");
        write("19-eh-continuations.txt", text.ToString());
    }

    private static void WriteRegionPhiCopyLegality(
        DeadCodeResult deadCode,
        Action<string, string> write)
    {
        var plan = RegionAwarePhiCopyLegalityAnalyzer.Analyze(deadCode);
        var verification = RegionAwarePhiCopyLegalityVerifier.Verify(plan);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Emitted copies: {plan.EmittedCopies}")
            .AppendLine($"Implicit EH variable states: {plan.ImplicitVariableStates}")
            .AppendLine($"Deferred finally leaves: {plan.DeferredLeaves}")
            .AppendLine($"Illegal copies: {plan.IllegalCopies}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var decision in plan.Decisions)
        {
            string edge = decision.Edge is null ? "entry"
                : $"B{decision.Edge.SourceBlockId}->B{decision.Edge.TargetBlockId}:"
                    + decision.Edge.Kind;
            text.AppendLine($"B{decision.TargetBlockId} %{decision.SourceValueId}->"
                + $"%{decision.PhiValueId} {edge} {decision.Disposition} "
                + $"placements={decision.AllowedPlacements} reason={decision.Reason}");
        }
        write("18-eh-phi-copy-legality.txt", text.ToString());
    }

    private static void WriteExceptionEntries(
        MethodDefinition target,
        SsaGraph ssa,
        Action<string, string> write)
    {
        if (target.DeclaringType?.DeclaringModule is not { } module)
            return;
        var model = ExceptionEntryModelBuilder.Build(module, ssa);
        var verification = ExceptionEntryModelVerifier.Verify(model);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.IsValid}")
            .AppendLine($"Entries: {model.Entries.Count}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var entry in model.Entries)
        {
            string exceptionObject = entry.ExceptionObject is null ? "empty-stack"
                : $"exception={entry.ExceptionObject.StaticType?.FullName ?? "<unresolved>"} "
                    + $"ssa=%{entry.ExceptionObject.SsaValueId?.ToString() ?? "none"}";
            text.AppendLine($"EH{entry.ExceptionRegionId} {entry.Kind} "
                + $"VM#{entry.InstructionIndex:D4} B{entry.BlockId} "
                + $"edge={entry.IncomingEdgeKind} {exceptionObject} path={entry.RegionPath}");
        }
        write("17-eh-entry-model.txt", text.ToString());
    }

    private static SsaGraph WriteSsa(
        MethodDefinition target,
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        Action<string, string> write)
    {
        var ssa = SsaGraphBuilder.Build(graph, analysis, target);
        var verification = SsaVerifier.Verify(ssa, analysis);
        var statistics = SsaVerifier.Statistics(ssa);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Reachable blocks: {statistics.ReachableBlocks}")
            .AppendLine($"Unreachable blocks: {statistics.UnreachableBlocks}")
            .AppendLine($"Values: {statistics.Values}")
            .AppendLine($"Phi nodes: {statistics.Phis}")
            .AppendLine($"Instructions: {statistics.Instructions}")
            .AppendLine($"Uses: {statistics.Uses}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);

        foreach (var block in ssa.Blocks)
        {
            text.AppendLine().AppendLine($"B{block.Id} reachable={block.Reachable}");
            if (!block.Reachable)
                continue;
            foreach (var phi in block.Phis)
            {
                string location = phi.LocationKind == SsaPhiLocationKind.Variable
                    ? phi.Variable?.ToString() ?? "variable"
                    : $"stack[{phi.StackSlot}]";
                string inputs = string.Join(", ", phi.Inputs.Select(input =>
                    input.Kind == SsaPhiInputKind.MethodEntry
                        ? $"entry:%{input.ValueId}"
                        : $"B{input.PredecessorBlockId}:%{input.ValueId}"));
                text.AppendLine($"  %{phi.Result.Id} = phi {location} ({inputs})");
            }
            foreach (var instruction in block.Instructions)
            {
                string outputs = instruction.Outputs.Count == 0 ? ""
                    : string.Join(",", instruction.Outputs.Select(id => $"%{id}")) + " = ";
                string inputs = string.Join(",", instruction.Inputs.Select(id => $"%{id}"));
                text.AppendLine($"  {outputs}{instruction.Operation.Code}({inputs}) "
                    + $"; VM#{instruction.Operation.VmInstructionIndex:D4}");
            }
            if (block.Terminator is { } terminator)
                text.AppendLine($"  TERM {terminator.Terminator.Kind}("
                    + string.Join(",", terminator.Inputs.Select(id => $"%{id}")) + ")");
        }
        write("13-ssa.txt", text.ToString());
        return ssa;
    }

    private static SccpResult WriteSccp(SsaGraph ssa, Action<string, string> write)
    {
        var result = SccpAnalyzer.Analyze(ssa);
        var verification = SccpVerifier.Verify(result);
        var statistics = SccpAnalyzer.Statistics(result);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Converged: {result.Converged}")
            .AppendLine($"Iterations: {result.Iterations}")
            .AppendLine($"Executable blocks: {statistics.ExecutableBlocks}")
            .AppendLine($"Executable edges: {statistics.ExecutableEdges}")
            .AppendLine($"Infeasible normal edges: {statistics.InfeasibleNormalEdges}")
            .AppendLine($"Constants: {statistics.Constants}")
            .AppendLine($"Overdefined: {statistics.Overdefined}")
            .AppendLine($"Undefined: {statistics.Undefined}")
            .AppendLine($"Folded terminators: {statistics.FoldedTerminators}")
            .AppendLine($"Folded pure calls: {statistics.FoldedPureCalls}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var block in ssa.Blocks.Where(block => block.Reachable))
        {
            string executable = result.ExecutableBlocks.Contains(block.Id) ? "yes" : "no";
            text.AppendLine().AppendLine($"B{block.Id} executable={executable}");
            foreach (var instruction in block.Instructions)
            {
                foreach (int output in instruction.Outputs)
                    text.AppendLine($"  %{output} {instruction.Operation.Code}: {result.Values[output]}");
            }
            if (block.Terminator is { } terminator)
            {
                var decision = SccpEvaluator.Decide(terminator, result.Values);
                if (decision.Known)
                    text.AppendLine($"  TERM folded taken={decision.ConditionalTaken} "
                        + $"switch={decision.SwitchIndex}");
            }
        }
        write("14-sccp.txt", text.ToString());
        return result;
    }

    private static DeadCodeResult WriteDeadCode(
        SccpResult sccp,
        Action<string, string> write)
    {
        var result = SsaDeadCodeAnalysis.Analyze(sccp);
        var verification = SsaDeadCodeVerifier.Verify(result);
        var statistics = SsaDeadCodeAnalysis.Statistics(result);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Executable instructions: {statistics.ExecutableInstructions}")
            .AppendLine($"Live instructions: {statistics.LiveInstructions}")
            .AppendLine($"Removable instructions: {statistics.RemovedInstructions}")
            .AppendLine($"Live values: {statistics.LiveValues}")
            .AppendLine($"Constant replacements: {statistics.ConstantReplacements}")
            .AppendLine($"Side-effect roots: {statistics.SideEffectRoots}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var block in sccp.Graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)))
        {
            text.AppendLine().AppendLine($"B{block.Id}");
            foreach (var instruction in block.Instructions)
            {
                string state = result.LiveInstructionIds.Contains(instruction.Id)
                    ? "LIVE" : "REMOVE";
                text.AppendLine($"  {state,-6} I{instruction.Id} "
                    + $"{instruction.Operation.Code}");
            }
        }
        if (result.ConstantReplacements.Count > 0)
        {
            text.AppendLine().AppendLine("Constant replacements:");
            foreach (var replacement in result.ConstantReplacements.OrderBy(pair => pair.Key))
                text.AppendLine($"  %{replacement.Key} = {replacement.Value ?? "null"}");
        }
        write("15-dce.txt", text.ToString());
        return result;
    }

    private static void WriteControlFlowSimplification(
        DeadCodeResult deadCode,
        Action<string, string> write)
    {
        var result = ControlFlowSimplifier.Analyze(deadCode);
        var verification = ControlFlowSimplificationVerifier.Verify(result);
        var statistics = ControlFlowSimplifier.Statistics(result);
        var text = new StringBuilder()
            .AppendLine($"Valid: {verification.Valid}")
            .AppendLine($"Retained blocks: {statistics.RetainedBlocks}")
            .AppendLine($"Removed blocks: {statistics.RemovedBlocks}")
            .AppendLine($"Retained edges: {statistics.RetainedEdges}")
            .AppendLine($"Folded terminators: {statistics.FoldedTerminators}")
            .AppendLine($"Finite cyclic dispatchers: {statistics.DispatcherBlocks}")
            .AppendLine($"Trivial redirects: {statistics.TrivialRedirects}");
        foreach (string error in verification.Errors)
            text.AppendLine("ERROR: " + error);
        foreach (var plan in result.FoldedTerminators)
            text.AppendLine($"FOLD B{plan.BlockId} {plan.OriginalKind} -> "
                + $"B{plan.SelectedEdge.TargetBlockId}");
        foreach (var dispatcher in result.Dispatchers)
        {
            string states = string.Join(", ", dispatcher.StateTargets
                .OrderBy(pair => pair.Key)
                .Select(pair => $"{pair.Key}->B{pair.Value.TargetBlockId}"));
            text.AppendLine($"DISPATCHER B{dispatcher.BlockId} "
                + $"selector=%{dispatcher.SelectorValueId}: {states}");
        }
        foreach (var redirect in result.TrivialRedirects)
            text.AppendLine($"REDIRECT B{redirect.BlockId} -> B{redirect.TargetBlockId} "
                + $"from [{string.Join(",", redirect.PredecessorBlockIds)}]");
        write("16-cfg-simplification.txt", text.ToString());
    }

    private static void WriteWorklist(
        WorklistAnalysisResult analysis,
        Action<string, string> write)
    {
        var text = new StringBuilder()
            .AppendLine($"Converged: {analysis.Converged}")
            .AppendLine($"Iterations: {analysis.Iterations}");
        foreach (var block in analysis.Graph.Blocks)
        {
            var state = analysis.Blocks[block.Id];
            text.AppendLine().AppendLine($"B{block.Id} processed={state.ProcessCount}")
                .AppendLine("  IN : " + state.Entry)
                .AppendLine("  OUT: " + state.Exit);
        }
        if (analysis.Diagnostics.Count > 0)
        {
            text.AppendLine().AppendLine("Diagnostics:");
            foreach (string diagnostic in analysis.Diagnostics)
                text.AppendLine("  " + diagnostic);
        }
        write("11-worklist-states.txt", text.ToString());
    }

    private static void WriteLegacyComparison(
        LegacyComparisonResult comparison,
        Action<string, string> write)
    {
        var text = new StringBuilder()
            .AppendLine($"Equivalent: {comparison.Count(LegacyComparisonKind.Equivalent)}")
            .AppendLine($"Compatible: {comparison.Count(LegacyComparisonKind.Compatible)}")
            .AppendLine($"Different: {comparison.Count(LegacyComparisonKind.Different)}")
            .AppendLine($"Unavailable: {comparison.Count(LegacyComparisonKind.Unavailable)}")
            .AppendLine($"Legacy linear artifacts: "
                + comparison.Count(LegacyDifferenceCategory.LegacyLinearObservationArtifact))
            .AppendLine($"Semantic transfer imprecision: "
                + comparison.Count(LegacyDifferenceCategory.SemanticTransferImprecision))
            .AppendLine($"Possible CFG/worklist errors: "
                + comparison.Count(LegacyDifferenceCategory.PossibleCfgOrWorklistError))
            .AppendLine($"Structurally unreachable blocks: "
                + comparison.Count(LegacyDifferenceCategory.StructurallyUnreachableBlock));
        foreach (var block in comparison.Blocks)
        {
            string classification = block.Classification.Category == LegacyDifferenceCategory.None
                ? ""
                : $" [{block.Classification.Category}/{block.Classification.ArtifactCause}]";
            text.AppendLine().AppendLine(
                $"B{block.BlockId} VM#{block.VmInstructionIndex:D4}: {block.Kind}{classification}");
            foreach (var difference in block.Differences)
                text.AppendLine("  " + difference.Message);
            if (block.Classification.Category != LegacyDifferenceCategory.None)
                text.AppendLine("  evidence: " + block.Classification.Evidence);
        }
        text.AppendLine().AppendLine(
            "OBSERVATIONAL ONLY: differences do not affect acceptance or emission.");
        write("12-legacy-comparison.txt", text.ToString());
    }

    private static void WriteSemanticIr(
        SemanticControlFlowGraph graph,
        Action<string, string> write)
    {
        var text = new StringBuilder();
        foreach (var block in graph.Blocks)
        {
            text.AppendLine($"B{block.Id} VM[{block.StartInstructionIndex}..{block.EndInstructionIndex}]");
            foreach (var operation in block.Operations)
                text.AppendLine($"  VM#{operation.VmInstructionIndex:D4} {operation.Code,-22} "
                    + $"semantics={operation.Semantics} operand={FormatOperand(operation.Operand)} "
                    + $"legacy={operation.LegacyDisplay}");
            text.AppendLine($"  terminator {block.Terminator.Kind} "
                + $"semantics={block.Terminator.Semantics}: {block.Terminator.LegacyDisplay}");
        }
        write("09-semantic-ir.txt", text.ToString());
    }

    private static void WriteBlocks(
        SemanticControlFlowGraph graph,
        DecodedMethod decoded,
        Action<string, string> write)
    {
        var text = new StringBuilder();
        foreach (var block in graph.Blocks)
        {
            text.AppendLine($"B{block.Id}: VM [{block.StartInstructionIndex}..{block.EndInstructionIndex}] "
                + $"regionPath={block.RegionPath}");
            for (int index = block.StartInstructionIndex; index <= block.EndInstructionIndex; index++)
                text.AppendLine($"  #{index:D4} {decoded.Instructions[index]}");
            foreach (var operation in block.Operations)
                text.AppendLine($"    {operation.Code}: {operation.LegacyDisplay}");
            text.AppendLine($"    TERM {block.Terminator.Kind}: {block.Terminator.LegacyDisplay}");
        }

        text.AppendLine("Edges:");
        foreach (var edge in graph.Edges)
        {
            string detail = edge.SwitchCaseIndex is { } caseIndex ? $" case={caseIndex}" : "";
            if (edge.ExceptionRegionId is { } regionId)
                detail += $" EH={regionId}";
            text.AppendLine($"B{edge.SourceBlockId} -> B{edge.TargetBlockId} "
                + $"kind={edge.Kind}{detail}");
        }
        write("03-blocks.txt", text.ToString());
    }

    private static void WriteDot(
        SemanticControlFlowGraph graph,
        Action<string, string> write)
    {
        var dot = new StringBuilder("digraph cfg {\n  rankdir=TB;\n");
        foreach (var block in graph.Blocks)
        {
            string label = $"B{block.Id} [{block.StartInstructionIndex}..{block.EndInstructionIndex}]"
                + $"\\n{block.RegionPath}\\n{block.Terminator.Kind}";
            dot.AppendLine($"  B{block.Id} [label=\"{Escape(label)}\"];");
        }
        foreach (var edge in graph.Edges)
        {
            string style = edge.ExceptionRegionId is null ? "solid" : "dashed";
            dot.AppendLine($"  B{edge.SourceBlockId} -> B{edge.TargetBlockId} "
                + $"[label=\"{edge.Kind}\", style={style}];");
        }
        dot.AppendLine("}");
        write("04-cfg.dot", dot.ToString());
    }

    private static void WriteValidation(
        SemanticControlFlowGraph graph,
        Action<string, string> write)
    {
        var errors = ControlFlowGraphValidator.Validate(graph);
        var text = new StringBuilder()
            .AppendLine($"Instructions: {graph.InstructionCount}")
            .AppendLine($"Blocks: {graph.Blocks.Count}")
            .AppendLine($"Edges: {graph.Edges.Count}")
            .AppendLine($"Exception regions: {graph.ExceptionRegions.Count}");
        if (errors.Count == 0)
            text.AppendLine("VALID: all formal CFG invariants passed");
        else
            foreach (string error in errors)
                text.AppendLine("ERROR: " + error);
        write("10-cfg-validation.txt", text.ToString());
    }

    private static string FormatOperand(object? operand) => operand switch
    {
        null => "none",
        Array values => "[" + string.Join(",", values.Cast<object?>()) + "]",
        _ => operand.ToString() ?? "?",
    };

    private static string Escape(string value) =>
        value.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
