namespace AgileDevirtualizer.Analysis;

internal enum EhSsaValidationSelection
{
    AllVerified,
    RuntimeProven,
    RuntimeProvenOrSameRegionEdgeCopies,
}

internal static class EhSsaValidationSelectionPolicy
{
    public static EhSsaActivationEligibility Evaluate(
        EhSsaShadowPlan plan,
        EhSsaValidationSelection selection) => selection switch
    {
        EhSsaValidationSelection.AllVerified => new(true,
            "all internally verified EH SSA shapes are selected"),
        EhSsaValidationSelection.RuntimeProven => EhSsaActivationPolicy.Evaluate(plan),
        EhSsaValidationSelection.RuntimeProvenOrSameRegionEdgeCopies =>
            EvaluateRuntimeOrCopies(plan),
        _ => new(false, $"unknown EH SSA validation selection {selection}"),
    };

    public static string Label(
        EhSsaValidationSelection selection,
        EhSsaShadowPlan plan) => selection switch
    {
        EhSsaValidationSelection.AllVerified => "validation-only EH SSA",
        EhSsaValidationSelection.RuntimeProven => "strict EH SSA",
        EhSsaValidationSelection.RuntimeProvenOrSameRegionEdgeCopies =>
            plan.TotalCopies == 0 ? "strict EH SSA" : "edge-copy candidate EH SSA",
        _ => "unknown EH SSA",
    };

    private static EhSsaActivationEligibility EvaluateRuntimeOrCopies(EhSsaShadowPlan plan)
    {
        var proven = EhSsaActivationPolicy.Evaluate(plan);
        return proven.Eligible ? proven : EhSsaEdgeCopyActivationPolicy.Evaluate(plan);
    }
}
