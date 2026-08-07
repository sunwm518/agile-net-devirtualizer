namespace AgileDevirtualizer.Analysis;

/// <summary>Sparse conditional constant propagation over verified observational SSA.</summary>
internal static class SccpAnalyzer
{
    private const int MaximumIterations = 100_000;

    public static SccpResult Analyze(SsaGraph graph)
    {
        var values = graph.Values.ToDictionary(value => value.Id,
            value => value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal
                or SsaValueKind.ExceptionObject
                ? SccpValue.Overdefined : SccpValue.Undefined);
        var executableBlocks = new HashSet<int>();
        var executableEdges = new HashSet<ControlFlowEdge>();
        var foldedPureCalls = new HashSet<int>();
        if (graph.Blocks.Count > 0 && graph.Blocks[0].Reachable)
            executableBlocks.Add(0);

        bool changed;
        int iterations = 0;
        do
        {
            changed = false;
            iterations++;
            foreach (var block in graph.Blocks.Where(block =>
                block.Reachable && executableBlocks.Contains(block.Id)))
            {
                foreach (var phi in block.Phis)
                {
                    var incoming = SccpValue.Undefined;
                    foreach (var input in phi.Inputs.Where(input =>
                        IsExecutablePhiInput(input, block.Id, executableEdges)))
                        incoming = SccpValue.Join(incoming, values[input.ValueId]);
                    changed |= Merge(values, phi.Result.Id, incoming);
                }

                foreach (var instruction in block.Instructions)
                {
                    if (instruction.Outputs.Count == 0)
                        continue;
                    var inputs = instruction.Inputs.Select(id => values[id]).ToArray();
                    foreach (int outputId in instruction.Outputs)
                    {
                        var evaluated = SccpEvaluator.Evaluate(instruction, inputs,
                            graph.Value(outputId).AbstractValue, out bool pureCall);
                        changed |= Merge(values, outputId, evaluated);
                        if (pureCall && evaluated.Kind == SccpValueKind.Constant)
                            foldedPureCalls.Add(instruction.Id);
                    }
                }

                var sourceBlock = graph.Source.Blocks[block.Id];
                var outgoing = SsaControlFlow.Outgoing(graph.Source, sourceBlock).ToArray();
                foreach (var edge in outgoing.Where(edge => IsExceptionEdge(edge.Kind)))
                    changed |= MarkExecutable(edge, executableEdges, executableBlocks);
                if (block.Terminator is not { } terminator)
                    continue;
                var normal = outgoing.Where(edge => !IsExceptionEdge(edge.Kind)).ToArray();
                var decision = SccpEvaluator.Decide(terminator, values);
                foreach (var edge in SelectNormalEdges(normal, terminator.Terminator, decision))
                    changed |= MarkExecutable(edge, executableEdges, executableBlocks);
            }
        } while (changed && iterations < MaximumIterations);

        return new SccpResult(graph, values, executableBlocks, executableEdges,
            !changed, iterations, foldedPureCalls.Count);
    }

    public static SccpStatistics Statistics(SccpResult result)
    {
        int infeasible = 0;
        int foldedTerminators = 0;
        foreach (var block in result.Graph.Blocks.Where(block =>
            block.Reachable && result.ExecutableBlocks.Contains(block.Id)))
        {
            var normal = SsaControlFlow.Outgoing(result.Graph.Source,
                    result.Graph.Source.Blocks[block.Id])
                .Where(edge => !IsExceptionEdge(edge.Kind)).ToArray();
            infeasible += normal.Count(edge => !result.ExecutableEdges.Contains(edge));
            if (block.Terminator is { } terminator
                && normal.Length > 1
                && SccpEvaluator.Decide(terminator, result.Values).Known)
                foldedTerminators++;
        }
        return new SccpStatistics(
            result.ExecutableBlocks.Count,
            result.ExecutableEdges.Count,
            infeasible,
            result.Values.Count(pair => pair.Value.Kind == SccpValueKind.Constant),
            result.Values.Count(pair => pair.Value.Kind == SccpValueKind.Overdefined),
            result.Values.Count(pair => pair.Value.Kind == SccpValueKind.Undefined),
            foldedTerminators,
            result.FoldedPureCalls);
    }

    private static bool IsExecutablePhiInput(
        SsaPhiInput input,
        int targetBlockId,
        IReadOnlySet<ControlFlowEdge> executableEdges)
    {
        if (input.Kind == SsaPhiInputKind.MethodEntry)
            return true;
        return executableEdges.Any(edge => edge.SourceBlockId == input.PredecessorBlockId
            && edge.TargetBlockId == targetBlockId);
    }

    private static IEnumerable<ControlFlowEdge> SelectNormalEdges(
        IReadOnlyList<ControlFlowEdge> normal,
        SemanticTerminator terminator,
        SccpTerminatorDecision decision)
    {
        if (!decision.Known)
            return normal;
        if (terminator.Kind == SemanticTerminatorKind.Conditional)
        {
            var kind = decision.ConditionalTaken
                ? ControlFlowEdgeKind.ConditionalTaken
                : ControlFlowEdgeKind.ConditionalFallThrough;
            return normal.Where(edge => edge.Kind == kind);
        }
        if (terminator.Kind == SemanticTerminatorKind.Switch
            && decision.SwitchIndex is { } index)
        {
            var selected = normal.Where(edge => edge.Kind == ControlFlowEdgeKind.SwitchCase
                && edge.SwitchCaseIndex == index).ToArray();
            return selected.Length > 0 ? selected
                : normal.Where(edge => edge.Kind == ControlFlowEdgeKind.SwitchDefault);
        }
        return normal;
    }

    private static bool MarkExecutable(
        ControlFlowEdge edge,
        ISet<ControlFlowEdge> edges,
        ISet<int> blocks)
    {
        bool changed = edges.Add(edge);
        changed |= blocks.Add(edge.TargetBlockId);
        return changed;
    }

    private static bool Merge(
        IDictionary<int, SccpValue> values,
        int valueId,
        SccpValue incoming)
    {
        var joined = SccpValue.Join(values[valueId], incoming);
        if (joined == values[valueId])
            return false;
        values[valueId] = joined;
        return true;
    }

    private static bool IsExceptionEdge(ControlFlowEdgeKind kind) =>
        ControlFlowEdgeSemantics.IsException(kind);
}
