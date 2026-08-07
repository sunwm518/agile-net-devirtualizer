using AgileDevirtualizer.Decode;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Builds explicit typed phi copies. The plan is deliberately conservative: every live operation
/// result has a private typed spill, keeping the CIL stack empty at every real and synthetic block
/// boundary. Local coalescing is a later, independently verifiable pass.
/// </summary>
internal static class SsaEdgeCopyPlanner
{
    public static SsaEdgeCopyPlan Plan(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        DecodedMethod decoded)
    {
        if (!ReferenceEquals(deadCode.Sccp.Graph, types.Graph) || !types.Converged)
            return SsaEdgeCopyPlan.Reject(deadCode, types,
                "CIL types do not belong to this SSA graph or did not converge");
        var graph = deadCode.Sccp.Graph;
        if (decoded.ExceptionHandlers.Count != 0 || graph.Source.ExceptionRegions.Count != 0)
            return SsaEdgeCopyPlan.Reject(deadCode, types,
                "edge-copy lowering does not model exception regions yet");

        var requirements = SsaLoweringRequirementAnalyzer.Analyze(deadCode.Sccp);
        var forbidden = SsaLoweringFeature.ExceptionRegion | SsaLoweringFeature.ExceptionObject
            | SsaLoweringFeature.ManagedPointer | SsaLoweringFeature.AddressOperation
            | SsaLoweringFeature.Prefix;
        if ((requirements.Features & forbidden) != 0)
            return SsaEdgeCopyPlan.Reject(deadCode, types,
                $"requires unsupported {requirements.Features & forbidden}");

        var executableIds = graph.Blocks.Where(block => block.Reachable
                && deadCode.Sccp.ExecutableBlocks.Contains(block.Id))
            .Select(block => block.Id).ToHashSet();
        if (!executableIds.Contains(0))
            return SsaEdgeCopyPlan.Reject(deadCode, types, "entry block is not executable");
        if (!SsaPhiBlockLayout.TryOrder(graph, deadCode.Sccp, executableIds,
            out var order, out string? layoutError))
            return SsaEdgeCopyPlan.Reject(deadCode, types, layoutError!);

        var phiTypes = new Dictionary<int, TypeSignature>();
        var edgeCopies = new Dictionary<ControlFlowEdge, List<SsaTypedPhiCopy>>();
        var entryCopies = new List<SsaTypedPhiCopy>();
        foreach (var block in graph.Blocks.Where(block => executableIds.Contains(block.Id)))
        {
            foreach (var phi in block.Phis.Where(phi =>
                deadCode.LiveValueIds.Contains(phi.Result.Id)
                && !deadCode.ConstantReplacements.ContainsKey(phi.Result.Id)))
            {
                if (!TryExact(types, phi.Result.Id, out var phiType))
                    return SsaEdgeCopyPlan.Reject(deadCode, types,
                        $"phi %{phi.Result.Id} has no exact CIL type ({types.Values[phi.Result.Id]})");
                phiTypes[phi.Result.Id] = phiType!;
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, deadCode.Sccp))
                {
                    if (!Compatible(types.Values[input.ValueId], phiType!))
                        return SsaEdgeCopyPlan.Reject(deadCode, types,
                            $"phi %{phi.Result.Id} input %{input.ValueId} has incompatible type "
                            + types.Values[input.ValueId]);
                    var copy = new SsaTypedPhiCopy(phi.Result.Id, input.ValueId, phiType!);
                    if (input.Kind == SsaPhiInputKind.MethodEntry)
                    {
                        entryCopies.Add(copy);
                        continue;
                    }
                    var matching = NormalExecutableEdges(deadCode, input.PredecessorBlockId!.Value)
                        .Where(edge => edge.TargetBlockId == block.Id).ToArray();
                    if (matching.Length == 0)
                        return SsaEdgeCopyPlan.Reject(deadCode, types,
                            $"phi %{phi.Result.Id} has no executable edge from "
                            + $"B{input.PredecessorBlockId} to B{block.Id}");
                    foreach (var edge in matching)
                    {
                        if (!edgeCopies.TryGetValue(edge, out var copies))
                            edgeCopies[edge] = copies = [];
                        copies.Add(copy);
                    }
                }
            }
        }

        var spills = new Dictionary<int, TypeSignature>();
        foreach (var instruction in graph.Blocks.Where(block => executableIds.Contains(block.Id))
            .SelectMany(block => block.Instructions)
            .Where(instruction => deadCode.LiveInstructionIds.Contains(instruction.Id)))
        {
            if (instruction.Outputs.Count > 1)
                return SsaEdgeCopyPlan.Reject(deadCode, types,
                    $"I{instruction.Id} has {instruction.Outputs.Count} outputs");
            foreach (int output in instruction.Outputs)
            {
                if (deadCode.ConstantReplacements.ContainsKey(output))
                    continue;
                if (!TryExact(types, output, out var type))
                    return SsaEdgeCopyPlan.Reject(deadCode, types,
                        $"operation value %{output} has no exact CIL type ({types.Values[output]})");
                spills[output] = type!;
            }
        }

        // A structural critical edge is split even when DCE made all of its phi copies dead. This
        // keeps edge placement explicit and lets later passes add/coalesce copies without changing
        // the CFG topology underneath them.
        foreach (var edge in deadCode.Sccp.ExecutableEdges.Where(edge =>
            !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)))
        {
            int outgoing = NormalExecutableEdges(deadCode, edge.SourceBlockId).Count();
            int incoming = NormalExecutableIncoming(deadCode, edge.TargetBlockId).Count();
            if (outgoing > 1 && incoming > 1)
                edgeCopies.TryAdd(edge, []);
        }

        var planned = new List<SsaEdgeCopy>();
        if (entryCopies.Count > 0)
            planned.Add(new SsaEdgeCopy(null, SsaEdgeCopyPlacement.MethodEntry,
                entryCopies.OrderBy(copy => copy.PhiValueId).ToArray()));
        foreach (var pair in edgeCopies.OrderBy(pair => pair.Key.SourceBlockId)
            .ThenBy(pair => pair.Key.TargetBlockId).ThenBy(pair => pair.Key.Kind)
            .ThenBy(pair => pair.Key.SwitchCaseIndex))
        {
            int outDegree = NormalExecutableEdges(deadCode, pair.Key.SourceBlockId).Count();
            int inDegree = NormalExecutableIncoming(deadCode, pair.Key.TargetBlockId).Count();
            var placement = outDegree == 1
                ? SsaEdgeCopyPlacement.SourceExit
                : inDegree == 1
                    ? SsaEdgeCopyPlacement.TargetEntry
                    : SsaEdgeCopyPlacement.SplitBlock;
            planned.Add(new SsaEdgeCopy(pair.Key, placement,
                pair.Value.OrderBy(copy => copy.PhiValueId).ToArray()));
        }

        return new SsaEdgeCopyPlan(deadCode, types, true, "eligible", order,
            phiTypes, spills, planned);
    }

    private static IEnumerable<ControlFlowEdge> NormalExecutableEdges(
        DeadCodeResult deadCode,
        int sourceBlockId) => deadCode.Sccp.ExecutableEdges.Where(edge =>
            edge.SourceBlockId == sourceBlockId
            && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));

    private static IEnumerable<ControlFlowEdge> NormalExecutableIncoming(
        DeadCodeResult deadCode,
        int targetBlockId) => deadCode.Sccp.ExecutableEdges.Where(edge =>
            edge.TargetBlockId == targetBlockId
            && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));

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

    private static bool Compatible(SsaCilType source, TypeSignature destination)
    {
        if (source.Kind == SsaCilTypeKind.Null)
            return !SafeIsValueType(destination);
        return source is { Kind: SsaCilTypeKind.Exact, Type: { } type }
            && type.FullName == destination.FullName;
    }

    private static bool SafeIsValueType(TypeSignature type)
    {
        try { return type.IsValueType; }
        catch { return false; }
    }
}
