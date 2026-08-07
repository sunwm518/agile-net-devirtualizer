using AgileDevirtualizer.Decode;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Conservative EH SSA plan. Mutable source variables retain their original CIL slots; only live
/// evaluation-stack phis receive edge copies. Critical EH copy edges remain an explicit rejection.
/// </summary>
internal static class EhSsaShadowPlanner
{
    public static EhSsaShadowPlan Plan(
        ModuleDefinition module,
        DecodedMethod decoded,
        DeadCodeResult deadCode,
        SsaCilTypeResult types)
    {
        var graph = deadCode.Sccp.Graph;
        var entries = ExceptionEntryModelBuilder.Build(module, graph);
        var continuations = ExceptionContinuationModelBuilder.Build(graph);
        var legality = RegionAwarePhiCopyLegalityAnalyzer.Analyze(deadCode);
        EhSsaShadowPlan Reject(string reason) => EhSsaShadowPlan.Reject(deadCode,
            types, entries, continuations, legality, reason);

        if (decoded.ExceptionHandlers.Count == 0 || graph.Source.ExceptionRegions.Count == 0)
            return Reject("EH shadow lowering requires at least one exception region");
        if (!ReferenceEquals(types.Graph, graph) || !types.Converged)
            return Reject("CIL types do not belong to this SSA graph or did not converge");
        var entryVerification = ExceptionEntryModelVerifier.Verify(entries);
        if (!entryVerification.IsValid)
            return Reject("invalid EH entries: " + string.Join("; ", entryVerification.Errors));
        var continuationVerification = ExceptionContinuationModelVerifier.Verify(continuations);
        if (!continuationVerification.Valid)
            return Reject("invalid EH continuations: "
                + string.Join("; ", continuationVerification.Errors));
        var legalityVerification = RegionAwarePhiCopyLegalityVerifier.Verify(legality);
        if (!legalityVerification.Valid || legality.IllegalCopies != 0)
            return Reject("invalid region-aware phi legality: "
                + string.Join("; ", legalityVerification.Errors));

        var executableIds = graph.Blocks.Where(block => block.Reachable
                && deadCode.Sccp.ExecutableBlocks.Contains(block.Id))
            .Select(block => block.Id).ToHashSet();
        if (!executableIds.Contains(0))
            return Reject("entry block is not executable");
        if (graph.Blocks.Any(block => block.Reachable && !executableIds.Contains(block.Id)))
            return Reject("reachable blocks are not all executable");
        foreach (int blockId in executableIds)
        {
            foreach (var edge in SsaControlFlow.Outgoing(graph.Source,
                graph.Source.Blocks[blockId]).Where(edge =>
                    !ControlFlowEdgeSemantics.IsException(edge.Kind)))
            {
                if (!deadCode.Sccp.ExecutableEdges.Contains(edge)
                    || !executableIds.Contains(edge.TargetBlockId))
                    return Reject($"B{blockId} has an infeasible normal edge");
            }
        }
        var order = executableIds.OrderBy(id =>
            graph.Source.Blocks[id].StartInstructionIndex).ToArray();
        var closure = EhSsaEmissionClosureBuilder.Build(deadCode);
        if (!closure.Valid)
            return Reject("invalid EH emission closure: " + closure.Reason);
        var functionPointers = EhFunctionPointerShadowModelBuilder.Build(graph, closure);
        if (!functionPointers.Valid)
            return Reject("invalid EH function-pointer model: " + functionPointers.Reason);
        legality = RegionAwarePhiCopyLegalityAnalyzer.Analyze(deadCode,
            closure.ValueIds, closure.Constants);
        legalityVerification = RegionAwarePhiCopyLegalityVerifier.Verify(legality);
        if (!legalityVerification.Valid || legality.IllegalCopies != 0)
            return Reject("invalid extended region-aware phi legality: "
                + string.Join("; ", legalityVerification.Errors));

        var variablePhis = new Dictionary<int, SsaVariableSlot>();
        var stackPhis = new Dictionary<int, TypeSignature>();
        var exceptionObjects = new Dictionary<int, TypeSignature>();
        var spills = new Dictionary<int, TypeSignature>();
        var copies = new Dictionary<ControlFlowEdge, List<SsaTypedPhiCopy>>();
        var entryCopies = new List<SsaTypedPhiCopy>();

        foreach (var entry in entries.Entries.Where(entry =>
            executableIds.Contains(entry.BlockId) && entry.ExceptionObject is not null))
        {
            if (entry.ExceptionObject!.SsaValueId is not { } valueId
                || !TryExact(types, valueId, out var type))
                return Reject($"EH{entry.ExceptionRegionId} {entry.Kind} has no exact exception type");
            exceptionObjects[valueId] = type!;
        }

        foreach (var block in graph.Blocks.Where(block => executableIds.Contains(block.Id)))
        foreach (var phi in block.Phis.Where(phi =>
            closure.ValueIds.Contains(phi.Result.Id)
            && !closure.Constants.ContainsKey(phi.Result.Id)))
        {
            if (phi.LocationKind == SsaPhiLocationKind.Variable)
            {
                if (phi.Variable is not { } variable)
                    return Reject($"variable phi %{phi.Result.Id} has no variable slot");
                variablePhis[phi.Result.Id] = variable;
                continue;
            }
            if (!EhStackPhiTypeInference.TryInfer(module, phi, deadCode.Sccp,
                types, out var phiType))
                return Reject($"stack phi %{phi.Result.Id} has no exact CIL type");
            stackPhis[phi.Result.Id] = phiType!;
            foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, deadCode.Sccp))
            {
                if (!EhStackPhiTypeInference.IsCompatible(module,
                    types.Values[input.ValueId], phiType!))
                    return Reject($"stack phi %{phi.Result.Id} has incompatible input %{input.ValueId}");
                var copy = new SsaTypedPhiCopy(phi.Result.Id, input.ValueId, phiType!);
                if (input.Kind == SsaPhiInputKind.MethodEntry)
                {
                    entryCopies.Add(copy);
                    continue;
                }
                var matching = deadCode.Sccp.ExecutableEdges.Where(edge =>
                    edge.SourceBlockId == input.PredecessorBlockId
                    && edge.TargetBlockId == block.Id
                    && (input.EdgeKind is null || edge.Kind == input.EdgeKind)).ToArray();
                if (matching.Length == 0)
                    return Reject($"stack phi %{phi.Result.Id} has no executable edge");
                foreach (var edge in matching)
                {
                    var decision = legality.Decisions.SingleOrDefault(candidate =>
                        candidate.PhiValueId == phi.Result.Id
                        && candidate.SourceValueId == input.ValueId
                        && Equals(candidate.Edge, edge));
                    if (decision?.Disposition != RegionPhiCopyDisposition.EmittedCopy)
                        return Reject($"stack phi %{phi.Result.Id} is not copy-safe on {edge.Kind}");
                    if (!copies.TryGetValue(edge, out var edgeCopies))
                        copies[edge] = edgeCopies = [];
                    edgeCopies.Add(copy);
                }
            }
        }

        foreach (var instruction in graph.Blocks.Where(block => executableIds.Contains(block.Id))
            .SelectMany(block => block.Instructions)
            .Where(instruction => closure.InstructionIds.Contains(instruction.Id)))
        foreach (int output in instruction.Outputs.Where(output =>
            closure.ValueIds.Contains(output) && !closure.Constants.ContainsKey(output)
            && !functionPointers.Values.ContainsKey(output)))
        {
            if (!TryExact(types, output, out var type))
                return Reject($"operation value %{output} has no exact CIL type ({types.Values[output]})");
            spills[output] = type!;
        }

        var planned = new List<SsaEdgeCopy>();
        if (entryCopies.Count > 0)
            planned.Add(new SsaEdgeCopy(null, SsaEdgeCopyPlacement.MethodEntry,
                entryCopies.OrderBy(copy => copy.PhiValueId).ToArray()));
        foreach (var pair in copies.OrderBy(pair => pair.Key.SourceBlockId)
            .ThenBy(pair => pair.Key.TargetBlockId).ThenBy(pair => pair.Key.Kind))
        {
            int outgoing = NormalEdges(deadCode, pair.Key.SourceBlockId).Count();
            int incoming = NormalIncoming(deadCode, pair.Key.TargetBlockId).Count();
            if (outgoing > 1 && incoming > 1)
                return Reject($"critical EH copy edge B{pair.Key.SourceBlockId}->B{pair.Key.TargetBlockId}");
            var placement = outgoing == 1
                ? SsaEdgeCopyPlacement.SourceExit : SsaEdgeCopyPlacement.TargetEntry;
            planned.Add(new SsaEdgeCopy(pair.Key, placement,
                pair.Value.OrderBy(copy => copy.PhiValueId).ToArray()));
        }

        return new EhSsaShadowPlan(deadCode, types, entries, continuations, legality,
            true, "eligible", order, closure.InstructionIds, closure.ValueIds,
            closure.Constants, variablePhis, stackPhis, exceptionObjects, spills,
            functionPointers.Values, planned);
    }

    private static IEnumerable<ControlFlowEdge> NormalEdges(
        DeadCodeResult deadCode,
        int blockId) => deadCode.Sccp.ExecutableEdges.Where(edge =>
        edge.SourceBlockId == blockId && !ControlFlowEdgeSemantics.IsException(edge.Kind));

    private static IEnumerable<ControlFlowEdge> NormalIncoming(
        DeadCodeResult deadCode,
        int blockId) => deadCode.Sccp.ExecutableEdges.Where(edge =>
        edge.TargetBlockId == blockId && !ControlFlowEdgeSemantics.IsException(edge.Kind));

    private static bool TryExact(
        SsaCilTypeResult types,
        int valueId,
        out TypeSignature? type)
    {
        if (types.Values[valueId] is { Kind: SsaCilTypeKind.Exact, Type: { } exact })
        {
            type = exact;
            return true;
        }
        type = null;
        return false;
    }

}
