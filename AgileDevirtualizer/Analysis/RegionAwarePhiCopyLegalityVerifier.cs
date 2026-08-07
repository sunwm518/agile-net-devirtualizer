namespace AgileDevirtualizer.Analysis;

internal sealed record RegionPhiCopyLegalityVerification(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class RegionAwarePhiCopyLegalityVerifier
{
    public static RegionPhiCopyLegalityVerification Verify(RegionPhiCopyLegalityPlan plan)
    {
        var errors = new List<string>();
        var keys = plan.Decisions.GroupBy(Key).ToArray();
        foreach (var duplicate in keys.Where(group => group.Count() != 1))
            errors.Add($"duplicate phi legality decision for {duplicate.Key}");
        foreach (var decision in plan.Decisions)
            VerifyDecision(decision, errors);
        VerifyCoverage(plan, keys.Select(group => group.Key).ToHashSet(), errors);
        return new RegionPhiCopyLegalityVerification(errors);
    }

    private static void VerifyDecision(
        RegionPhiCopyDecision decision,
        List<string> errors)
    {
        if (decision.InputKind == SsaPhiInputKind.MethodEntry)
        {
            if (decision.Edge is not null
                || decision.Disposition != RegionPhiCopyDisposition.EmittedCopy
                || decision.AllowedPlacements != RegionCopyPlacement.MethodEntry)
                errors.Add($"phi %{decision.PhiValueId} has invalid method-entry placement");
            return;
        }
        if (decision.Edge is not { } edge || decision.Transition is not { } transition)
        {
            if (decision.Disposition != RegionPhiCopyDisposition.Illegal)
                errors.Add($"phi %{decision.PhiValueId} has no edge/transition");
            return;
        }
        if (!transition.Valid)
        {
            if (decision.Disposition != RegionPhiCopyDisposition.Illegal)
                errors.Add($"phi %{decision.PhiValueId} accepts invalid transition {transition.Reason}");
            return;
        }
        if (ControlFlowEdgeSemantics.IsException(edge.Kind))
        {
            var expected = decision.PhiLocation == SsaPhiLocationKind.Variable
                ? RegionPhiCopyDisposition.ImplicitVariableState
                : RegionPhiCopyDisposition.Illegal;
            if (decision.Disposition != expected || decision.AllowedPlacements != RegionCopyPlacement.None)
                errors.Add($"phi %{decision.PhiValueId} mishandles exceptional edge {edge.Kind}");
            return;
        }
        var normalExpected = transition.RequiresFinallyUnwind
            ? RegionPhiCopyDisposition.RequiresLeaveUnwind
            : RegionPhiCopyDisposition.EmittedCopy;
        if (decision.Disposition != normalExpected)
            errors.Add($"phi %{decision.PhiValueId} has {decision.Disposition}, expected {normalExpected}");
        if (normalExpected == RegionPhiCopyDisposition.EmittedCopy
            && (decision.AllowedPlacements & (RegionCopyPlacement.SourceExit
                | RegionCopyPlacement.TargetEntry | RegionCopyPlacement.SplitBlock)) == 0)
            errors.Add($"phi %{decision.PhiValueId} has no legal normal-edge placement");
    }

    private static void VerifyCoverage(
        RegionPhiCopyLegalityPlan plan,
        IReadOnlySet<string> actual,
        List<string> errors)
    {
        var sccp = plan.DeadCode.Sccp;
        foreach (var block in sccp.Graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)))
        foreach (var phi in block.Phis.Where(phi =>
            plan.RequiredValueIds.Contains(phi.Result.Id)
            && !plan.ConstantValues.ContainsKey(phi.Result.Id)))
        foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp))
        {
            if (input.Kind == SsaPhiInputKind.MethodEntry)
            {
                string key = Key(block.Id, phi.Result.Id, input.ValueId, null);
                if (!actual.Contains(key)) errors.Add($"missing {key}");
                continue;
            }
            foreach (var edge in sccp.ExecutableEdges.Where(edge =>
                edge.SourceBlockId == input.PredecessorBlockId
                && edge.TargetBlockId == block.Id
                && (input.EdgeKind is null || edge.Kind == input.EdgeKind)))
            {
                string key = Key(block.Id, phi.Result.Id, input.ValueId, edge);
                if (!actual.Contains(key)) errors.Add($"missing {key}");
            }
        }
    }

    private static string Key(RegionPhiCopyDecision decision) => Key(
        decision.TargetBlockId, decision.PhiValueId, decision.SourceValueId, decision.Edge);

    private static string Key(
        int blockId,
        int phiValueId,
        int sourceValueId,
        ControlFlowEdge? edge) => $"B{blockId}:%{sourceValueId}->%{phiValueId}:"
        + (edge is null ? "entry" : $"B{edge.SourceBlockId}:{edge.Kind}:{edge.SwitchCaseIndex}");
}
