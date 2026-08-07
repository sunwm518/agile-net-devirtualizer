namespace AgileDevirtualizer.Analysis;

/// <summary>
/// One observational checkpoint from the optimization pipeline. It never participates in candidate
/// selection; it only explains why an already verified route was selected, rejected or skipped.
/// </summary>
internal sealed record OptimizationAttempt(
    string Stage,
    string Outcome,
    string Reason,
    SsaLoweringFeature Requirements = SsaLoweringFeature.None,
    CilStructuralQuality? Baseline = null,
    CilStructuralQuality? Candidate = null);
