using AgileDevirtualizer.Decode;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record OptimizedSemanticEmissionResult(
    CilMethodBody Body,
    bool Optimized,
    int EliminatedDispatchers,
    int FoldedConstantBranches,
    string Layout,
    int TypedSpills = 0,
    string Quality = "",
    IReadOnlyList<OptimizationAttempt>? Attempts = null);

/// <summary>
/// Production gate for SSA-driven optimizations. Every analysis layer is independently verified;
/// any unsupported shape returns the ordinary semantic emitter, never a partially rewritten body.
/// </summary>
internal static class OptimizedSemanticEmitter
{
    public static OptimizedSemanticEmissionResult Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult worklist,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        bool enableTypedSsa = false,
        bool enablePhiSsa = false,
        bool enableEdgeSsaShadow = false)
    {
        var attempts = new List<OptimizationAttempt>();
        try
        {
            var ssa = SsaGraphBuilder.Build(graph, worklist, target);
            Require(SsaVerifier.Verify(ssa, worklist).Errors, "SSA");
            var sccp = SccpAnalyzer.Analyze(ssa);
            Require(SccpVerifier.Verify(sccp).Errors, "SCCP");
            var deadCode = SsaDeadCodeAnalysis.Analyze(sccp);
            Require(SsaDeadCodeVerifier.Verify(deadCode).Errors, "DCE");
            var simplification = ControlFlowSimplifier.Analyze(deadCode);
            Require(ControlFlowSimplificationVerifier.Verify(simplification).Errors,
                "CFG simplification");
            var dispatchers = DispatcherEliminationPlanner.Analyze(simplification);
            var branches = ConstantBranchEliminationPlanner.Analyze(simplification);
            if (dispatchers.Rejections.Count > 0 || branches.Rejections.Count > 0)
            {
                string reason = string.Join(" | ", dispatchers.Rejections
                    .Concat(branches.Rejections).Take(5));
                attempts.Add(new OptimizationAttempt("dispatcher-rewrite", "rejected",
                    reason));
                return Lossless();
            }
            if (dispatchers.Eliminations.Count == 0 && branches.Eliminations.Count == 0)
            {
                attempts.Add(new OptimizationAttempt("dispatcher-rewrite", "skipped",
                    "no dispatcher or constant branch was proven removable"));
                return enableTypedSsa || enablePhiSsa || enableEdgeSsaShadow
                    ? SmallestSsaLowering(ssa, deadCode, graph,
                        SemanticCfgEmitter.Emit(module, target, decoded, graph,
                            tempLocalTypes), "lossless", false, 0, 0)
                    : Lossless();
            }

            attempts.Add(new OptimizationAttempt("dispatcher-rewrite", "selected",
                $"dispatchers={dispatchers.Eliminations.Count}; "
                + $"constant-branches={branches.Eliminations.Count}"));

            var rewrite = OptimizedGraphRewriter.Rewrite(dispatchers, branches);
            Require(OptimizedGraphVerifier.Verify(rewrite).Errors, "optimized CFG");
            var linear = SemanticCfgEmitter.Emit(module, target, decoded, rewrite.Graph,
                tempLocalTypes);
            CilMethodBody selected = linear;
            string layout = "linear";
            if (decoded.ExceptionHandlers.Count == 0)
            {
                selected = PrunedSemanticCfgEmitter.Emit(module, target, decoded,
                    rewrite.Graph, tempLocalTypes);
                layout = "pruned";
            }
            if (enableTypedSsa || enablePhiSsa || enableEdgeSsaShadow)
            {
                // Dispatcher/constant-branch elimination changes both reachability and value
                // congruence. Rebuild every data-flow layer over that rewritten graph; reusing the
                // pre-rewrite SSA would attach phi inputs to edges that no longer exist.
                try
                {
                    var rewrittenWorklist = WorklistAnalyzer.Analyze(rewrite.Graph);
                    if (!rewrittenWorklist.Converged)
                        throw new InvalidOperationException(
                            "post-rewrite worklist did not converge");
                    var rewrittenSsa = SsaGraphBuilder.Build(rewrite.Graph,
                        rewrittenWorklist, target);
                    Require(SsaVerifier.Verify(rewrittenSsa, rewrittenWorklist).Errors,
                        "post-rewrite SSA");
                    var rewrittenSccp = SccpAnalyzer.Analyze(rewrittenSsa);
                    Require(SccpVerifier.Verify(rewrittenSccp).Errors,
                        "post-rewrite SCCP");
                    var rewrittenDeadCode = SsaDeadCodeAnalysis.Analyze(rewrittenSccp);
                    Require(SsaDeadCodeVerifier.Verify(rewrittenDeadCode).Errors,
                        "post-rewrite DCE");
                    return SmallestSsaLowering(rewrittenSsa, rewrittenDeadCode,
                        rewrite.Graph, selected, layout, true,
                        rewrite.Statistics.EliminatedDispatchers,
                        rewrite.Statistics.FoldedConstantBranches);
                }
                catch (Exception exception)
                {
                    attempts.Add(new OptimizationAttempt("post-dispatch-ssa", "rejected",
                        $"{exception.GetType().Name}: {exception.Message}"));
                    // The verified dispatcher body remains the safe local fallback. A failure in
                    // this optional second optimization tier must never discard a valid rewrite.
                }
            }
            return new OptimizedSemanticEmissionResult(selected, true,
                rewrite.Statistics.EliminatedDispatchers,
                rewrite.Statistics.FoldedConstantBranches, layout,
                Attempts: attempts);
        }
        catch (Exception exception)
        {
            attempts.Add(new OptimizationAttempt("semantic-optimization", "rejected",
                $"{exception.GetType().Name}: {exception.Message}"));
            return Lossless();
        }

        OptimizedSemanticEmissionResult Lossless() => new(
            SemanticCfgEmitter.Emit(module, target, decoded, graph, tempLocalTypes),
            false, 0, 0, "lossless", Attempts: attempts);

        /// <summary>
        /// Installs the structurally best independently verified SSA lowering. The quality gate can
        /// accept bounded instruction growth when it removes decompiler-visible scaffolding.
        /// </summary>
        OptimizedSemanticEmissionResult SmallestSsaLowering(
            SsaGraph ssa,
            DeadCodeResult deadCode,
            SemanticControlFlowGraph loweringGraph,
            CilMethodBody baseline,
            string baselineLayout,
            bool baselineOptimized,
            int eliminatedDispatchers,
            int foldedConstantBranches)
        {
            var types = SsaCilTypeAnalyzer.Analyze(module, target, decoded, tempLocalTypes, ssa);
            var requirements = SsaLoweringRequirementAnalyzer.Analyze(deadCode.Sccp);
            attempts.Add(new OptimizationAttempt("ssa-requirements", "observed",
                $"blocks={requirements.ExecutableBlocks}; variable-phis={requirements.VariablePhis}; "
                + $"stack-phis={requirements.EvaluationStackPhis}; "
                + $"critical-edges={requirements.CriticalEdges}; "
                + $"multi-use={requirements.MultiUseValues}; "
                + $"unknown-types={requirements.UnknownValueTypes}",
                requirements.Features));
            var best = baseline;
            string layout = baselineLayout;
            int spills = 0;
            bool optimized = baselineOptimized;
            string quality = "";

            // Verification-only route: explicitly requested artifacts install the independently
            // verified edge-copy body even while it is larger. Normal production selection never
            // reaches this branch, so the strict "smaller body" gate remains unchanged.
            if (enableEdgeSsaShadow)
            {
                var edgePlan = SsaEdgeCopyPlanner.Plan(deadCode, types, decoded);
                var expressionPlan = SsaPhiLoweringPlanner.Plan(deadCode, types, decoded,
                    tempLocalTypes);
                var edgeVerification = SsaEdgeCopyVerifier.Verify(edgePlan);
                var expressionVerification = SsaPhiLoweringVerifier.Verify(expressionPlan);
                if (edgePlan.Eligible && edgeVerification.Valid && expressionPlan.Eligible
                    && expressionVerification.Valid)
                {
                    attempts.Add(new OptimizationAttempt("ssa-edge-shadow", "selected",
                        "verified edge-copy and phi plans", requirements.Features));
                    var edgeBody = CoalescedSsaEdgeEmitter.Emit(module, target, decoded,
                        loweringGraph, edgePlan, expressionPlan, tempLocalTypes);
                    return new OptimizedSemanticEmissionResult(edgeBody, true,
                        eliminatedDispatchers, foldedConstantBranches,
                        "ssa-edge-shadow", expressionPlan.SpillTypes.Count,
                        Attempts: attempts);
                }
                attempts.Add(new OptimizationAttempt("ssa-edge-shadow", "rejected",
                    PlanFailure(edgePlan.Eligible, edgePlan.Reason, edgeVerification.Errors,
                        expressionPlan.Eligible, expressionPlan.Reason,
                        expressionVerification.Errors), requirements.Features));
            }

            if (enableTypedSsa)
            {
                var schedule = TypedSsaExpressionScheduler.Plan(deadCode, types);
                if (!schedule.Eligible)
                {
                    attempts.Add(new OptimizationAttempt("typed-ssa", "rejected",
                        schedule.Reason, requirements.Features));
                }
                else
                {
                    var typed = TypedStraightLineSsaEmitter.Emit(module, target, decoded,
                        schedule, tempLocalTypes);
                    var typedQuality = CilStructuralQualityGate.Evaluate(best, spills,
                        typed, schedule.SpillTypes.Count);
                    attempts.Add(new OptimizationAttempt("typed-ssa",
                        typedQuality.Better ? "selected" : "rejected",
                        typedQuality.Reason, requirements.Features,
                        typedQuality.Baseline, typedQuality.Candidate));
                    if (typedQuality.Better)
                    {
                        (best, layout, spills, optimized) =
                            (typed, "typed-ssa", schedule.SpillTypes.Count, true);
                        quality = $"{typedQuality.Reason}:{typedQuality.Summary}";
                    }
                }
            }

            if (enablePhiSsa)
            {
                var plan = SsaPhiLoweringPlanner.Plan(deadCode, types, decoded,
                    tempLocalTypes);
                var planVerification = SsaPhiLoweringVerifier.Verify(plan);
                if (!plan.Eligible || !planVerification.Valid)
                {
                    attempts.Add(new OptimizationAttempt("ssa-phi", "rejected",
                        !plan.Eligible ? plan.Reason
                            : string.Join(" | ", planVerification.Errors.Take(5)),
                        requirements.Features));
                }
                else
                {
                    if (requirements.Features.HasFlag(SsaLoweringFeature.MultipleBlocks))
                    {
                        var edgeCandidate = SsaEdgeCopyPlanner.Plan(deadCode, types, decoded);
                        var edgeVerification = SsaEdgeCopyVerifier.Verify(edgeCandidate);
                        if (edgeCandidate.Eligible && edgeVerification.Valid)
                        {
                            var edgeLowered = CoalescedSsaEdgeEmitter.Emit(module, target,
                                decoded, loweringGraph, edgeCandidate, plan, tempLocalTypes);
                            var edgeQuality = CilStructuralQualityGate.Evaluate(best, spills,
                                edgeLowered, plan.SpillTypes.Count);
                            attempts.Add(new OptimizationAttempt("ssa-edge",
                                edgeQuality.Better ? "selected" : "rejected",
                                edgeQuality.Reason, requirements.Features,
                                edgeQuality.Baseline, edgeQuality.Candidate));
                            if (edgeQuality.Better)
                            {
                                (best, layout, spills, optimized) = (edgeLowered,
                                    baselineOptimized ? "post-dispatch-ssa-edge" : "ssa-edge",
                                    plan.SpillTypes.Count, true);
                                quality = $"{edgeQuality.Reason}:{edgeQuality.Summary}";
                            }
                        }
                        else
                        {
                            attempts.Add(new OptimizationAttempt("ssa-edge", "rejected",
                                !edgeCandidate.Eligible ? edgeCandidate.Reason
                                    : string.Join(" | ", edgeVerification.Errors.Take(5)),
                                requirements.Features));
                        }
                    }

                    var lowered = TypedSsaCfgEmitter.Emit(module, target, decoded,
                        loweringGraph, plan, tempLocalTypes);
                    var phiQuality = CilStructuralQualityGate.Evaluate(best, spills,
                        lowered, plan.SpillTypes.Count);
                    attempts.Add(new OptimizationAttempt("ssa-phi",
                        phiQuality.Better ? "selected" : "rejected",
                        phiQuality.Reason, requirements.Features,
                        phiQuality.Baseline, phiQuality.Candidate));
                    if (phiQuality.Better)
                    {
                        (best, layout, spills, optimized) =
                            (lowered, baselineOptimized
                                ? "post-dispatch-ssa-phi" : "ssa-phi",
                                plan.SpillTypes.Count, true);
                        quality = $"{phiQuality.Reason}:{phiQuality.Summary}";
                    }
                }
            }

            return new OptimizedSemanticEmissionResult(best, optimized,
                eliminatedDispatchers, foldedConstantBranches, layout, spills, quality,
                attempts);
        }
    }

    private static string PlanFailure(bool edgeEligible, string edgeReason,
        IReadOnlyList<string> edgeErrors, bool expressionEligible, string expressionReason,
        IReadOnlyList<string> expressionErrors)
    {
        if (!edgeEligible)
            return "edge plan: " + edgeReason;
        if (edgeErrors.Count > 0)
            return "edge verification: " + string.Join(" | ", edgeErrors.Take(5));
        if (!expressionEligible)
            return "phi plan: " + expressionReason;
        return "phi verification: " + string.Join(" | ", expressionErrors.Take(5));
    }

    private static void Require(IReadOnlyList<string> errors, string stage)
    {
        if (errors.Count > 0)
            throw new InvalidOperationException($"{stage} verification failed: "
                + string.Join(" | ", errors.Take(5)));
    }
}
