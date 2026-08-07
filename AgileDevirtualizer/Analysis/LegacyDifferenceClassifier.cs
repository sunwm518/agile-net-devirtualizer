namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Assigns contradictory observations to one of three audit buckets. Only a precise, converged,
/// structurally valid formal state with legacy-only surplus stack entries may be classified as a
/// legacy linear-observation artifact. Everything else remains visible as imprecision or a possible
/// CFG/worklist defect.
/// </summary>
internal static class LegacyDifferenceClassifier
{
    public static LegacyDifferenceClassification Classify(
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        BasicBlock block,
        AbstractState formal,
        BlockLegacyComparison comparison,
        IReadOnlyList<BlockLegacyComparison> precedingComparisons)
    {
        if (comparison.Kind != LegacyComparisonKind.Different)
            return LegacyDifferenceClassification.None;

        if (!analysis.Converged || ControlFlowGraphValidator.Validate(graph).Count > 0
            || formal.Stack is null)
        {
            return new LegacyDifferenceClassification(
                LegacyDifferenceCategory.PossibleCfgOrWorklistError,
                LegacyArtifactCause.None,
                "the formal graph did not provide a converged, structurally valid stack shape");
        }

        if (formal.IsImprecise || block.Operations.Any(operation =>
                operation.Code == SemanticOperationCode.Other))
        {
            return new LegacyDifferenceClassification(
                LegacyDifferenceCategory.SemanticTransferImprecision,
                LegacyArtifactCause.None,
                "the semantic transfer marked this block imprecise or contains an unmodelled operation");
        }

        var heightDifferences = comparison.Differences
            .Where(difference => difference.Kind == LegacyStateDifferenceKind.StackHeight)
            .ToArray();
        bool legacyOnlySurplus = heightDifferences.Length == comparison.Differences.Count
            && heightDifferences.Length > 0
            && heightDifferences.All(difference =>
                difference.LegacyStackHeight > difference.FormalStackHeight);
        if (!legacyOnlySurplus)
        {
            return new LegacyDifferenceClassification(
                LegacyDifferenceCategory.PossibleCfgOrWorklistError,
                LegacyArtifactCause.None,
                "a known type/local contradiction or a formal-only stack value needs CFG/transfer audit");
        }

        int surplus = heightDifferences.Sum(difference =>
            difference.LegacyStackHeight!.Value - difference.FormalStackHeight!.Value);
        var (cause, evidence) = ExplainLegacySurplus(
            graph, block, precedingComparisons, surplus);
        if (cause == LegacyArtifactCause.UnresolvedPreciseSurplus)
        {
            return new LegacyDifferenceClassification(
                LegacyDifferenceCategory.PossibleCfgOrWorklistError, cause, evidence);
        }
        return new LegacyDifferenceClassification(
            LegacyDifferenceCategory.LegacyLinearObservationArtifact, cause, evidence);
    }

    private static (LegacyArtifactCause Cause, string Evidence) ExplainLegacySurplus(
        SemanticControlFlowGraph graph,
        BasicBlock block,
        IReadOnlyList<BlockLegacyComparison> precedingComparisons,
        int surplus)
    {
        bool compoundConsumption = block.Terminator.Kind == SemanticTerminatorKind.Throw
            && block.Operations.Any(operation => operation.Code == SemanticOperationCode.NewObject)
            || block.Operations.Any(operation => operation.Code is
                SemanticOperationCode.Call or SemanticOperationCode.CallVirtual
                or SemanticOperationCode.NewObject);
        if (compoundConsumption)
        {
            return (LegacyArtifactCause.CompoundHandlerShadowStack,
                $"legacy shadow retained {surplus} surplus value(s) across compound "
                    + "call/constructor/terminator stack effects while semantic transfer stayed precise");
        }

        var previous = precedingComparisons.LastOrDefault(candidate =>
            candidate.VmInstructionIndex == block.StartInstructionIndex - 1);
        if (previous?.Classification.Category ==
            LegacyDifferenceCategory.StructurallyUnreachableBlock)
        {
            return (LegacyArtifactCause.UnreachableLinearCarry,
                $"legacy linear scan carried {surplus} surplus value(s) through the "
                    + "preceding VM instruction even though that block has no incoming CFG edge");
        }
        if (previous?.Classification.Category ==
            LegacyDifferenceCategory.LegacyLinearObservationArtifact)
        {
            return (LegacyArtifactCause.PropagatedLinearCarry,
                $"legacy linear scan propagated {surplus} surplus value(s) from the "
                    + "already-contaminated preceding VM instruction");
        }

        if (block.StartInstructionIndex > 0)
        {
            var linearPrevious = graph.BlockContaining(block.StartInstructionIndex - 1);
            bool predecessorFlowsHere = graph.Edges.Any(edge =>
                edge.SourceBlockId == linearPrevious.Id && edge.TargetBlockId == block.Id
                && !ControlFlowEdgeSemantics.IsException(edge.Kind));
            if (!predecessorFlowsHere)
            {
                return (LegacyArtifactCause.NonEdgeLinearCarry,
                    $"legacy linear scan carried {surplus} surplus value(s) across "
                        + "consecutive VM indices that are not connected by a normal CFG edge");
            }
        }

        return (LegacyArtifactCause.UnresolvedPreciseSurplus,
            $"legacy shadow retained {surplus} surplus value(s) despite a precise, "
                + "converged semantic stack effect");
    }
}
