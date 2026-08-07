namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Runtime-candidate gate for EH methods whose only unproven lowering operation is an
/// evaluation-stack phi copy. The first admitted class is intentionally narrow: a normal,
/// non-critical edge whose source and target have the exact same EH region path.
/// </summary>
internal static class EhSsaEdgeCopyActivationPolicy
{
    public static EhSsaActivationEligibility Evaluate(EhSsaShadowPlan plan)
    {
        if (!plan.Eligible)
            return Reject(plan.Reason);
        if (plan.TotalCopies == 0)
            return Reject("method has no EH evaluation-stack phi copies");
        if (plan.FunctionPointers.Count != 0)
            return Reject("function-pointer rematerialization is a separate runtime proof");
        var unsupported = plan.DeadCode.Sccp.Graph.Source.ExceptionRegions
            .Select(region => region.ClauseKind).Distinct()
            .Where(kind => kind is not ExceptionClauseKind.Catch
                and not ExceptionClauseKind.Finally).ToArray();
        if (unsupported.Length != 0)
            return Reject("EH clause kinds remain shadow-only: "
                + string.Join(", ", unsupported));
        if (plan.Continuations.EndFilters.Count != 0)
            return Reject("endfilter remains shadow-only");

        var graph = plan.DeadCode.Sccp.Graph.Source;
        foreach (var copyPlan in plan.EdgeCopies)
        {
            if (copyPlan.Edge is not { } edge)
                return Reject("method-entry phi copies are not an EH runtime candidate");
            if (copyPlan.Placement is not SsaEdgeCopyPlacement.SourceExit
                and not SsaEdgeCopyPlacement.TargetEntry)
                return Reject($"{copyPlan.Placement} phi-copy placement is not runtime-proven");
            if (ControlFlowEdgeSemantics.IsException(edge.Kind))
                return Reject("exception-dispatch edges cannot carry emitted phi copies");

            var transition = RegionTransitionClassifier.Classify(graph, edge);
            if (!transition.Valid || transition.Kind != RegionTransitionKind.SameRegion
                || transition.RequiresFinallyUnwind
                || !transition.Source.Frames.SequenceEqual(transition.Target.Frames))
                return Reject($"B{edge.SourceBlockId}->B{edge.TargetBlockId} crosses an EH boundary");
            var requiredPlacement = copyPlan.Placement == SsaEdgeCopyPlacement.SourceExit
                ? RegionCopyPlacement.SourceExit : RegionCopyPlacement.TargetEntry;
            if ((transition.AllowedPlacements & requiredPlacement) == 0)
                return Reject($"{copyPlan.Placement} is illegal on B{edge.SourceBlockId}->"
                    + $"B{edge.TargetBlockId}");
            if (copyPlan.Copies.Count == 0)
                return Reject("empty edge-copy group");
        }

        return new EhSsaActivationEligibility(true,
            "same-region EH evaluation-stack phi copies are a runtime candidate");

        static EhSsaActivationEligibility Reject(string reason) => new(false, reason);
    }
}
