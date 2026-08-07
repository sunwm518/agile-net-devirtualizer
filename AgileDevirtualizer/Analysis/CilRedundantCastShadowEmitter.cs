using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;

namespace AgileDevirtualizer.Analysis;

internal sealed record CilRedundantCastShadowResult(
    CilMethodBody Candidate,
    CilRedundantCastAnalysis Analysis,
    int Removed,
    CilStructuralQualityDecision Quality,
    bool Valid,
    string Reason)
{
    public bool Better => Valid && Removed > 0 && Quality.Better;
}

/// <summary>
/// Creates and verifies a detached CIL candidate. The source body is never edited and no
/// instruction is reordered; the only possible mutation is deletion of a proven redundant
/// conversion that is neither a branch target nor an EH boundary.
/// </summary>
internal static class CilRedundantCastShadowEmitter
{
    public static CilRedundantCastShadowResult Emit(MethodDefinition target,
        CilMethodBody baseline)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(baseline);
        var analysis = CilRedundantCastAnalyzer.Analyze(target, baseline);
        var candidate = CilMethodBodyCloner.Clone(baseline);
        var unchanged = CilStructuralQualityGate.Evaluate(baseline, 0, candidate, 0);
        if (analysis.Removable == 0)
            return new CilRedundantCastShadowResult(candidate, analysis, 0, unchanged,
                true, "no conversion is proven redundant");

        try
        {
            int removed = 0;
            var pass = analysis;
            for (int iteration = 0; iteration < 16; iteration++)
            {
                var removable = pass.Conversions.Where(item => item.Removable)
                    .Select(item => item.InstructionIndex).OrderByDescending(index => index)
                    .ToArray();
                if (removable.Length == 0)
                    break;
                foreach (int index in removable)
                    candidate.Instructions.RemoveAt(index);
                removed += removable.Length;
                candidate.Instructions.CalculateOffsets();
                pass = CilRedundantCastAnalyzer.Analyze(target, candidate);
                if (iteration == 15 && pass.Removable > 0)
                    throw new InvalidOperationException(
                        "redundant-conversion cleanup did not reach a fixed point");
            }

            var owner = new MethodDefinition(target.Name, target.Attributes,
                target.Signature ?? throw new InvalidOperationException("target has no signature"),
                verify: false);
            owner.CilMethodBody = candidate;
            candidate.Instructions.CalculateOffsets();
            candidate.VerifyLabels(calculateOffsets: false);
            candidate.ComputeMaxStack();
            CilTypeSafetyValidator.Validate(candidate);
            var quality = CilStructuralQualityGate.Evaluate(baseline, 0, candidate, 0);
            return new CilRedundantCastShadowResult(candidate, analysis, removed, quality,
                true, quality.Better
                    ? $"verified fixed-point candidate removes {removed} conversion(s)"
                    : "verified candidate rejected by structural quality gate: " + quality.Reason);
        }
        catch (Exception exception)
        {
            return new CilRedundantCastShadowResult(candidate, analysis, 0, unchanged,
                false, $"candidate rejected ({exception.GetType().Name}: {exception.Message})");
        }
    }
}
