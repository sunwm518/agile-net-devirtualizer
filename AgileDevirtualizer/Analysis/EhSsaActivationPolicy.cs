namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaActivationEligibility(bool Eligible, string Reason);

/// <summary>
/// Runtime-evidence gate for production opt-in. The shadow model deliberately understands more
/// than this policy activates: filter/fault and cross-region edge-copy lowering stay observational
/// until a real protected artifact exercises those exact serialized/runtime forms.
/// </summary>
internal static class EhSsaActivationPolicy
{
    public static EhSsaActivationEligibility Evaluate(EhSsaShadowPlan plan)
    {
        if (!plan.Eligible)
            return Reject(plan.Reason);
        var verification = EhSsaShadowPlanVerifier.Verify(plan);
        if (!verification.Valid)
            return Reject("invalid EH SSA plan: " + string.Join("; ", verification.Errors));
        if (plan.TotalCopies != 0)
            return EhSsaEdgeCopyActivationPolicy.Evaluate(plan);
        if (plan.FunctionPointers.Count != 0)
            return EhSsaFunctionPointerActivationPolicy.Evaluate(plan);
        var unsupported = plan.DeadCode.Sccp.Graph.Source.ExceptionRegions
            .Select(region => region.ClauseKind).Distinct()
            .Where(kind => kind is not ExceptionClauseKind.Catch
                and not ExceptionClauseKind.Finally).ToArray();
        if (unsupported.Length != 0)
            return Reject("EH clause kinds remain shadow-only: "
                + string.Join(", ", unsupported));
        if (plan.Continuations.EndFilters.Count != 0)
            return Reject("endfilter remains shadow-only");
        return new EhSsaActivationEligibility(true,
            "runtime-proven catch/finally shape with no EH edge copies");

        static EhSsaActivationEligibility Reject(string reason) => new(false, reason);
    }
}
