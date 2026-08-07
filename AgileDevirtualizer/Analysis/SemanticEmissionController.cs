using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Builds, validates and installs a method body directly from Semantic IR. Failure leaves the
/// original VM-backed body installed; this production route never builds or consults legacy CIL.
/// </summary>
internal static class SemanticEmissionController
{
    public static CfgEmissionDecision TryActivate(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        Func<CilMethodBody>? semanticFactory = null,
        bool optimize = true,
        bool enableTypedSsa = false,
        bool enablePhiSsa = false,
        bool enableEdgeSsaShadow = false,
        bool enableRedundantCastShadow = false,
        bool enableRedundantCastCleanup = false)
    {
        var originalBody = target.CilMethodBody;
        SemanticControlFlowGraph graph;
        WorklistAnalysisResult analysis;
        CfgEmissionEligibility eligibility;
        try
        {
            graph = ControlFlowGraphBuilder.Build(decoded, lifted);
            var graphErrors = ControlFlowGraphValidator.Validate(graph);
            analysis = WorklistAnalyzer.Analyze(graph);
            eligibility = CfgEmissionPolicy.Evaluate(graph, graphErrors, analysis);
        }
        catch (Exception exception)
        {
            return Failure(CfgControlFlowFeatures.None,
                $"analysis failed ({exception.GetType().Name}: {exception.Message})");
        }

        if (!eligibility.Candidate)
            return new CfgEmissionDecision(CfgEmissionOutcome.NotSelected,
                eligibility.Features, eligibility.Reason);
        if (!eligibility.Eligible)
            return Failure(eligibility.Features, eligibility.Reason);

        try
        {
            OptimizedSemanticEmissionResult? optimized = null;
            var body = semanticFactory?.Invoke();
            if (body is null && optimize)
            {
                optimized = OptimizedSemanticEmitter.Emit(module, target, decoded, graph,
                    analysis, tempLocalTypes, enableTypedSsa, enablePhiSsa,
                    enableEdgeSsaShadow);
                body = optimized.Body;
            }
            body ??= SemanticCfgEmitter.Emit(module, target, decoded, graph, tempLocalTypes);
            if (!ReferenceEquals(target.CilMethodBody, originalBody))
                throw new InvalidOperationException(
                    "detached semantic emitter changed the installed body");

            CilRedundantCastPipelineResult? castCleanup = null;
            IReadOnlyList<OptimizationAttempt> attempts = optimized?.Attempts ?? [];
            if (enableRedundantCastShadow || enableRedundantCastCleanup)
            {
                castCleanup = CilRedundantCastPipeline.Run(target, body,
                    enableRedundantCastCleanup);
                body = castCleanup.Body;
                attempts = attempts.Append(castCleanup.Attempt).ToArray();
            }

            target.CilMethodBody = body;
            if (!ReferenceEquals(target.CilMethodBody, body))
                return Failure(eligibility.Features, "semantic body was not installed");
            string reason = optimized is { Optimized: true }
                ? $"optimized CIL installed; dispatchers={optimized.EliminatedDispatchers}; "
                    + $"constant-branches={optimized.FoldedConstantBranches}; "
                    + $"typed-spills={optimized.TypedSpills}; layout={optimized.Layout}"
                    + (string.IsNullOrEmpty(optimized.Quality)
                        ? "" : $"; quality={optimized.Quality}")
                : "independently validated and installed";
            if (castCleanup?.Activated == true)
                reason += $"; removed-safe-conversions={castCleanup.Shadow.Removed}";
            return new CfgEmissionDecision(CfgEmissionOutcome.Activated,
                eligibility.Features, reason, optimized?.Optimized == true,
                attempts);
        }
        catch (Exception exception)
        {
            return Failure(eligibility.Features,
                $"semantic emission failed ({exception.GetType().Name}: {exception.Message})");
        }

        CfgEmissionDecision Failure(CfgControlFlowFeatures features, string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, originalBody))
                target.CilMethodBody = originalBody;
            return new CfgEmissionDecision(CfgEmissionOutcome.SemanticFailure, features, reason);
        }
    }
}
