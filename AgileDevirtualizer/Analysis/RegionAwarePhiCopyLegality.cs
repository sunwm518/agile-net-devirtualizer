namespace AgileDevirtualizer.Analysis;

internal enum RegionPhiCopyDisposition
{
    EmittedCopy,
    ImplicitVariableState,
    RequiresLeaveUnwind,
    Illegal,
}

internal sealed record RegionPhiCopyDecision(
    int TargetBlockId,
    int PhiValueId,
    SsaPhiLocationKind PhiLocation,
    int SourceValueId,
    SsaPhiInputKind InputKind,
    ControlFlowEdge? Edge,
    RegionPhiCopyDisposition Disposition,
    RegionCopyPlacement AllowedPlacements,
    RegionTransition? Transition,
    string Reason);

internal sealed record RegionPhiCopyLegalityPlan(
    DeadCodeResult DeadCode,
    IReadOnlySet<int> RequiredValueIds,
    IReadOnlyDictionary<int, object?> ConstantValues,
    IReadOnlyList<RegionPhiCopyDecision> Decisions)
{
    public int EmittedCopies => Decisions.Count(decision =>
        decision.Disposition == RegionPhiCopyDisposition.EmittedCopy);
    public int ImplicitVariableStates => Decisions.Count(decision =>
        decision.Disposition == RegionPhiCopyDisposition.ImplicitVariableState);
    public int DeferredLeaves => Decisions.Count(decision =>
        decision.Disposition == RegionPhiCopyDisposition.RequiresLeaveUnwind);
    public int IllegalCopies => Decisions.Count(decision =>
        decision.Disposition == RegionPhiCopyDisposition.Illegal);
}

/// <summary>
/// Classifies every live phi input by CLI region legality. It does not create locals, split blocks,
/// or participate in emission.
/// </summary>
internal static class RegionAwarePhiCopyLegalityAnalyzer
{
    public static RegionPhiCopyLegalityPlan Analyze(
        DeadCodeResult deadCode,
        IReadOnlySet<int>? requiredValueIds = null,
        IReadOnlyDictionary<int, object?>? constantValues = null)
    {
        var sccp = deadCode.Sccp;
        var graph = sccp.Graph;
        var decisions = new List<RegionPhiCopyDecision>();
        foreach (var block in graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)))
        {
            foreach (var phi in block.Phis.Where(phi =>
                (requiredValueIds ?? deadCode.LiveValueIds).Contains(phi.Result.Id)
                && !(constantValues ?? deadCode.ConstantReplacements)
                    .ContainsKey(phi.Result.Id)))
            {
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp))
                {
                    if (input.Kind == SsaPhiInputKind.MethodEntry)
                    {
                        decisions.Add(new RegionPhiCopyDecision(block.Id, phi.Result.Id,
                            phi.LocationKind, input.ValueId, input.Kind, null,
                            RegionPhiCopyDisposition.EmittedCopy, RegionCopyPlacement.MethodEntry,
                            null, "method-entry initialization"));
                        continue;
                    }

                    var matching = sccp.ExecutableEdges.Where(edge =>
                        edge.SourceBlockId == input.PredecessorBlockId
                        && edge.TargetBlockId == block.Id
                        && (input.EdgeKind is null || edge.Kind == input.EdgeKind)).ToArray();
                    if (matching.Length == 0)
                    {
                        decisions.Add(new RegionPhiCopyDecision(block.Id, phi.Result.Id,
                            phi.LocationKind, input.ValueId, input.Kind, null,
                            RegionPhiCopyDisposition.Illegal, RegionCopyPlacement.None, null,
                            "phi input has no executable CFG edge"));
                        continue;
                    }
                    foreach (var edge in matching)
                        decisions.Add(ForEdge(graph.Source, block, phi, input, edge));
                }
            }
        }
        return new RegionPhiCopyLegalityPlan(deadCode,
            requiredValueIds ?? deadCode.LiveValueIds,
            constantValues ?? deadCode.ConstantReplacements,
            decisions);
    }

    private static RegionPhiCopyDecision ForEdge(
        SemanticControlFlowGraph source,
        SsaBlock target,
        SsaPhi phi,
        SsaPhiInput input,
        ControlFlowEdge edge)
    {
        var transition = RegionTransitionClassifier.Classify(source, edge);
        if (!transition.Valid)
            return Decision(RegionPhiCopyDisposition.Illegal,
                RegionCopyPlacement.None, transition.Reason);
        if (ControlFlowEdgeSemantics.IsException(edge.Kind))
        {
            return phi.LocationKind == SsaPhiLocationKind.Variable
                ? Decision(RegionPhiCopyDisposition.ImplicitVariableState,
                    RegionCopyPlacement.None,
                    "CLR preserves the existing local/argument slot at exception entry")
                : Decision(RegionPhiCopyDisposition.Illegal, RegionCopyPlacement.None,
                    "exception entry stacks are CLI-created and cannot be implemented by phi copies");
        }
        if (transition.RequiresFinallyUnwind)
            return Decision(RegionPhiCopyDisposition.RequiresLeaveUnwind,
                RegionCopyPlacement.None,
                "copy timing is deferred until leave/finally continuation is explicit");
        return Decision(RegionPhiCopyDisposition.EmittedCopy,
            transition.AllowedPlacements, transition.Reason);

        RegionPhiCopyDecision Decision(
            RegionPhiCopyDisposition disposition,
            RegionCopyPlacement placements,
            string reason) => new(target.Id, phi.Result.Id, phi.LocationKind,
                input.ValueId, input.Kind, edge, disposition, placements, transition, reason);
    }
}
