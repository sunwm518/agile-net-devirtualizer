using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal enum CfgEmissionOutcome
{
    NotSelected,
    Activated,
    SemanticFailure,
    LegacyFallback,
}

internal sealed record CfgEmissionDecision(
    CfgEmissionOutcome Outcome,
    CfgControlFlowFeatures Features,
    string Reason,
    bool Optimized = false,
    IReadOnlyList<OptimizationAttempt>? Attempts = null);

/// <summary>
/// Test-only legacy oracle: compares a detached semantic body with an installed legacy body and
/// restores legacy on every unsuccessful path. Production uses SemanticEmissionController.
/// </summary>
internal static class LegacyOracleEmissionController
{
    public static CfgEmissionDecision TryActivate(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        CilMethodBody legacyBody,
        Func<CilMethodBody>? shadowFactory = null)
    {
        if (!ReferenceEquals(target.CilMethodBody, legacyBody))
        {
            return new CfgEmissionDecision(CfgEmissionOutcome.LegacyFallback,
                CfgControlFlowFeatures.None, "legacy body is not installed");
        }

        SemanticControlFlowGraph graph;
        CfgEmissionEligibility eligibility;
        try
        {
            graph = ControlFlowGraphBuilder.Build(decoded, lifted);
            var graphErrors = ControlFlowGraphValidator.Validate(graph);
            var analysis = WorklistAnalyzer.Analyze(graph);
            eligibility = CfgEmissionPolicy.Evaluate(graph, graphErrors, analysis);
        }
        catch (Exception exception)
        {
            return Fallback(CfgControlFlowFeatures.None,
                $"analysis failed ({exception.GetType().Name}: {exception.Message})");
        }

        if (!eligibility.Candidate)
            return new CfgEmissionDecision(CfgEmissionOutcome.NotSelected,
                eligibility.Features, eligibility.Reason);
        if (!eligibility.Eligible)
            return Fallback(eligibility.Features, eligibility.Reason);

        try
        {
            var shadow = shadowFactory?.Invoke()
                ?? SemanticCfgEmitter.Emit(module, target, decoded, graph, tempLocalTypes);
            var comparison = ShadowCfgBodyComparer.Compare(legacyBody, shadow);
            if (!comparison.Equivalent)
            {
                string detail = string.Join(" | ", comparison.Differences.Take(3));
                return Fallback(eligibility.Features,
                    "shadow differs from legacy: " + detail);
            }

            target.CilMethodBody = shadow;
            if (!ReferenceEquals(target.CilMethodBody, shadow))
                return Fallback(eligibility.Features, "shadow body was not installed");
            return new CfgEmissionDecision(CfgEmissionOutcome.Activated,
                eligibility.Features, "validated and structurally equivalent");
        }
        catch (Exception exception)
        {
            return Fallback(eligibility.Features,
                $"shadow failed ({exception.GetType().Name}: {exception.Message})");
        }

        CfgEmissionDecision Fallback(CfgControlFlowFeatures features, string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, legacyBody))
                target.CilMethodBody = legacyBody;
            return new CfgEmissionDecision(CfgEmissionOutcome.LegacyFallback, features, reason);
        }
    }
}
