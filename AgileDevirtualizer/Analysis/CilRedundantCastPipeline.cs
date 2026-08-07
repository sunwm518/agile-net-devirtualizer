using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;

namespace AgileDevirtualizer.Analysis;

internal sealed record CilRedundantCastPipelineResult(
    CilMethodBody Body,
    CilRedundantCastShadowResult Shadow,
    OptimizationAttempt Attempt,
    bool Activated);

/// <summary>Shared shadow/activation gate for ordinary and exception-aware semantic emission.</summary>
internal static class CilRedundantCastPipeline
{
    public static CilRedundantCastPipelineResult Run(MethodDefinition target,
        CilMethodBody baseline, bool activate)
    {
        var shadow = CilRedundantCastShadowEmitter.Emit(target, baseline);
        string counts = $"castclass={shadow.Analysis.CastClass}; box={shadow.Analysis.Box}; "
            + $"unbox.any={shadow.Analysis.UnboxAny}; numeric={shadow.Analysis.Numeric}; "
            + $"proven-removable={shadow.Removed}";
        bool selected = activate && shadow.Better;
        string outcome = !shadow.Valid ? "rejected"
            : selected ? "selected"
            : shadow.Better ? "observed" : "skipped";
        string reason = counts + "; " + shadow.Reason
            + (shadow.Better && !activate ? "; activation disabled" : string.Empty);
        var attempt = new OptimizationAttempt("redundant-cast-shadow", outcome,
            reason, Baseline: shadow.Quality.Baseline,
            Candidate: shadow.Quality.Candidate);
        // The observational path never touches the synthetic owner's relationship. Activation is
        // explicit, so only then detach the exact body that reached the fixed point and passed all
        // validators; cloning it can lose offset-sensitive EH boundary information.
        var selectedBody = baseline;
        if (selected)
        {
            if (shadow.Candidate.Owner is not { } validationOwner)
                throw new InvalidOperationException(
                    "validated cast-cleanup candidate has no temporary owner");
            validationOwner.CilMethodBody = null;
            selectedBody = shadow.Candidate;
            selectedBody.Instructions.CalculateOffsets();
        }
        return new CilRedundantCastPipelineResult(
            selectedBody, shadow, attempt, selected);
    }
}
