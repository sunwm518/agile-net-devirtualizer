using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Validation-only bridge that materializes a detached EH SSA body in an isolated output artifact.
/// The normal semantic route never calls this controller. Every failed proof restores the original
/// VM-backed body, and there is deliberately no legacy fallback that could hide an EH SSA failure.
/// </summary>
internal static class EhSsaValidationEmissionController
{
    public static CfgEmissionDecision TryActivate(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        EhSsaValidationSelection selection = EhSsaValidationSelection.AllVerified,
        bool enableRedundantCastShadow = false,
        bool enableRedundantCastCleanup = false)
    {
        var originalBody = target.CilMethodBody;
        if (decoded.ExceptionHandlers.Count == 0)
        {
            return new CfgEmissionDecision(CfgEmissionOutcome.NotSelected,
                CfgControlFlowFeatures.None, "method has no exception regions");
        }

        try
        {
            var graph = ControlFlowGraphBuilder.Build(decoded, lifted);
            var graphErrors = ControlFlowGraphValidator.Validate(graph);
            if (graphErrors.Count != 0)
                return Failure("invalid CFG: " + string.Join("; ", graphErrors));
            var worklist = WorklistAnalyzer.Analyze(graph);
            if (!worklist.Converged)
                return Failure("worklist did not converge");
            var ssa = SsaGraphBuilder.Build(graph, worklist, target);
            var ssaVerification = SsaVerifier.Verify(ssa, worklist);
            if (!ssaVerification.Valid)
                return Failure("invalid SSA: " + string.Join("; ", ssaVerification.Errors));
            var deadCode = SsaDeadCodeAnalysis.Analyze(SccpAnalyzer.Analyze(ssa));
            var deadVerification = SsaDeadCodeVerifier.Verify(deadCode);
            if (!deadVerification.Valid)
                return Failure("invalid DCE: " + string.Join("; ", deadVerification.Errors));
            var types = SsaCilTypeAnalyzer.Analyze(module, target, decoded,
                tempLocalTypes, ssa);
            var plan = EhSsaShadowPlanner.Plan(module, decoded, deadCode, types);
            if (!plan.Eligible)
                return Failure("EH SSA plan rejected: " + plan.Reason);
            var planVerification = EhSsaShadowPlanVerifier.Verify(plan);
            if (!planVerification.Valid)
                return Failure("invalid EH SSA plan: "
                    + string.Join("; ", planVerification.Errors));
            var activation = EhSsaValidationSelectionPolicy.Evaluate(plan, selection);
            if (!activation.Eligible)
                return Failure("EH SSA activation policy rejected: " + activation.Reason);

            var interferenceCoalescing = EhSsaInterferenceCoalescingEmitter.EmitBest(module, target,
                decoded, graph, plan, tempLocalTypes);
            var crossBlockCoalescing = interferenceCoalescing.CrossBlockCoalescing;
            var expressionScheduling = crossBlockCoalescing.ExpressionScheduling;
            var localCoalescing = expressionScheduling.LocalCoalescing;
            var attempts = new List<OptimizationAttempt>
            {
                new("eh-ssa", "selected",
                    $"blocks={plan.BlockOrder.Count}; copies={plan.TotalCopies}; "
                    + $"spills={plan.OperationSpillTypes.Count}",
                    SsaLoweringFeature.ExceptionRegion),
                new("eh-local-coalescing",
                    localCoalescing.Optimized ? "selected" : "rejected",
                    localCoalescing.Reason, SsaLoweringFeature.ExceptionRegion),
                new("eh-expression-scheduling",
                    expressionScheduling.Optimized ? "selected" : "rejected",
                    expressionScheduling.Reason, SsaLoweringFeature.ExceptionRegion),
                new("eh-cross-block-coalescing",
                    crossBlockCoalescing.Optimized ? "selected" : "rejected",
                    crossBlockCoalescing.Reason, SsaLoweringFeature.ExceptionRegion),
                new("eh-interference-coalescing",
                    interferenceCoalescing.Optimized ? "selected" : "rejected",
                    interferenceCoalescing.Reason, SsaLoweringFeature.ExceptionRegion)
            };
            CilRedundantCastPipelineResult? castCleanup = null;
            var body = interferenceCoalescing.Body;
            if (enableRedundantCastShadow || enableRedundantCastCleanup)
            {
                castCleanup = CilRedundantCastPipeline.Run(target, body,
                    enableRedundantCastCleanup);
                attempts.Add(castCleanup.Attempt);
                body = castCleanup.Body;
            }
            if (!ReferenceEquals(target.CilMethodBody, originalBody))
                return Failure("detached EH SSA emitter changed the target body");
            target.CilMethodBody = body;
            return new CfgEmissionDecision(CfgEmissionOutcome.Activated,
                CfgEmissionPolicy.DetectFeatures(graph),
                $"{EhSsaValidationSelectionPolicy.Label(selection, plan)} "
                    + $"installed; blocks={plan.BlockOrder.Count}; "
                    + $"copies={plan.TotalCopies}; spills={plan.OperationSpillTypes.Count}; "
                    + (localCoalescing.Optimized
                        ? $"eh-locals=coalesced; removed-instructions="
                            + $"{localCoalescing.RemovedInstructions}; "
                            + $"removed-locals={localCoalescing.RemovedLocals}; "
                            + $"removed-casts={localCoalescing.RemovedCasts}"
                        : $"eh-locals=baseline ({localCoalescing.Reason})")
                    + "; " + (expressionScheduling.Optimized
                        ? $"eh-expressions=forwarded; values="
                            + $"{expressionScheduling.ForwardedValues}; "
                            + $"expression-instructions="
                            + $"{expressionScheduling.RemovedInstructions}; "
                            + $"expression-locals={expressionScheduling.RemovedLocals}"
                        : $"eh-expressions=baseline ({expressionScheduling.Reason})")
                    + "; " + (crossBlockCoalescing.Optimized
                        ? $"eh-cross-block=coalesced; cross-block-instructions="
                            + $"{crossBlockCoalescing.RemovedInstructions}; "
                            + $"cross-block-locals={crossBlockCoalescing.RemovedLocals}"
                        : $"eh-cross-block=baseline ({crossBlockCoalescing.Reason})")
                    + "; " + (interferenceCoalescing.Optimized
                        ? $"eh-interference=coalesced; interference-locals="
                            + $"{interferenceCoalescing.RemovedLocals}"
                        : $"eh-interference=baseline ({interferenceCoalescing.Reason})")
                    + (castCleanup?.Activated == true
                        ? $"; removed-safe-conversions={castCleanup.Shadow.Removed}"
                        : string.Empty),
                Optimized: true,
                Attempts: attempts);
        }
        catch (Exception exception)
        {
            return Failure($"EH SSA validation emission failed "
                + $"({exception.GetType().Name}: {exception.Message})");
        }

        CfgEmissionDecision Failure(string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, originalBody))
                target.CilMethodBody = originalBody;
            return new CfgEmissionDecision(CfgEmissionOutcome.SemanticFailure,
                CfgControlFlowFeatures.ExceptionRegions, reason);
        }
    }
}
