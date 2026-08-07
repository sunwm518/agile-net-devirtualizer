using AgileDevirtualizer.Lift;

namespace AgileDevirtualizer.Analysis;

internal enum LegacyComparisonKind
{
    Equivalent,
    Compatible,
    Different,
    Unavailable,
}

internal enum LegacyStateDifferenceKind
{
    StackShape,
    StackHeight,
    StackValue,
    LocalValue,
}

internal sealed record LegacyStateDifference(
    LegacyStateDifferenceKind Kind,
    string Message,
    int? FormalStackHeight = null,
    int? LegacyStackHeight = null);

internal enum LegacyDifferenceCategory
{
    None,
    LegacyLinearObservationArtifact,
    SemanticTransferImprecision,
    PossibleCfgOrWorklistError,
    StructurallyUnreachableBlock,
}

internal enum LegacyArtifactCause
{
    None,
    CompoundHandlerShadowStack,
    NonEdgeLinearCarry,
    PropagatedLinearCarry,
    UnreachableLinearCarry,
    UnresolvedPreciseSurplus,
}

internal sealed record LegacyDifferenceClassification(
    LegacyDifferenceCategory Category,
    LegacyArtifactCause ArtifactCause,
    string Evidence)
{
    public static LegacyDifferenceClassification None { get; } =
        new(LegacyDifferenceCategory.None, LegacyArtifactCause.None,
            "not a contradictory comparison");
}

internal sealed record BlockLegacyComparison(
    int BlockId,
    int VmInstructionIndex,
    LegacyComparisonKind Kind,
    IReadOnlyList<LegacyStateDifference> Differences,
    LegacyDifferenceClassification Classification);

internal sealed record LegacyComparisonResult(
    IReadOnlyList<BlockLegacyComparison> Blocks)
{
    public int Count(LegacyComparisonKind kind) => Blocks.Count(block => block.Kind == kind);
    public int Count(LegacyDifferenceCategory category) =>
        Blocks.Count(block => block.Classification.Category == category);
}

/// <summary>
/// Compares the fixed-point exit state of every formal block with the state observed after the
/// same VM instruction in the legacy linear lifting pass. Unknown dimensions are compatible, not
/// equal; contradictory known dimensions are reported as differences. Results never gate output.
/// </summary>
internal static class LegacyStateComparer
{
    public static LegacyComparisonResult Compare(
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        IReadOnlyList<LegacyStateSnapshot> legacySnapshots)
    {
        var snapshots = legacySnapshots
            .GroupBy(snapshot => snapshot.VmInstructionIndex)
            .ToDictionary(group => group.Key, group => group.Last());
        var comparisons = new List<BlockLegacyComparison>(graph.Blocks.Count);

        foreach (var block in graph.Blocks)
        {
            if (!analysis.Blocks.TryGetValue(block.Id, out var states)
                || !snapshots.TryGetValue(block.EndInstructionIndex, out var legacy))
            {
                comparisons.Add(new BlockLegacyComparison(block.Id, block.EndInstructionIndex,
                    LegacyComparisonKind.Unavailable, Array.Empty<LegacyStateDifference>(),
                    LegacyDifferenceClassification.None));
                continue;
            }
            if (!states.Exit.Reachable)
            {
                bool hasIncomingEdge = graph.Incoming(block).Any();
                var unreachableClassification = hasIncomingEdge
                    ? new LegacyDifferenceClassification(
                        LegacyDifferenceCategory.PossibleCfgOrWorklistError,
                        LegacyArtifactCause.None,
                        "worklist left a block unreachable despite one or more incoming CFG edges")
                    : new LegacyDifferenceClassification(
                        LegacyDifferenceCategory.StructurallyUnreachableBlock,
                        LegacyArtifactCause.None,
                        "non-entry block has no incoming normal or exceptional CFG edge");
                comparisons.Add(new BlockLegacyComparison(block.Id, block.EndInstructionIndex,
                    LegacyComparisonKind.Unavailable, Array.Empty<LegacyStateDifference>(),
                    unreachableClassification));
                continue;
            }

            var comparison = CompareBlock(block, states.Exit, legacy);
            var classification = LegacyDifferenceClassifier.Classify(
                graph, analysis, block, states.Exit, comparison, comparisons);
            comparisons.Add(comparison with { Classification = classification });
        }
        return new LegacyComparisonResult(comparisons);
    }

    private static BlockLegacyComparison CompareBlock(
        BasicBlock block,
        AbstractState formal,
        LegacyStateSnapshot legacy)
    {
        var differences = new List<LegacyStateDifference>();
        bool usedUnknown = formal.IsImprecise;

        if (formal.Stack is null)
        {
            differences.Add(new LegacyStateDifference(LegacyStateDifferenceKind.StackShape,
                "formal stack shape is conflicting/unknown"));
            return Result(LegacyComparisonKind.Compatible);
        }
        if (formal.Stack.Count != legacy.StackBottomToTop.Count)
        {
            differences.Add(new LegacyStateDifference(LegacyStateDifferenceKind.StackHeight,
                $"stack height formal={formal.Stack.Count} "
                    + $"legacy={legacy.StackBottomToTop.Count}",
                formal.Stack.Count, legacy.StackBottomToTop.Count));
            return Result(LegacyComparisonKind.Different);
        }

        for (int index = 0; index < formal.Stack.Count; index++)
        {
            var legacyValue = FromLegacy(legacy.StackBottomToTop[index]);
            var relation = CompareValue(formal.Stack[index], legacyValue);
            if (relation == ValueRelation.Different)
                differences.Add(new LegacyStateDifference(LegacyStateDifferenceKind.StackValue,
                    $"stack[{index}] formal={formal.Stack[index]} legacy={legacyValue}"));
            else if (relation == ValueRelation.Compatible)
                usedUnknown = true;
        }

        foreach (var pair in formal.Locals.Where(pair => !pair.Key.Temporary))
        {
            if (!legacy.KnownLocalTypes.TryGetValue(pair.Key.Index, out var legacyType))
            {
                usedUnknown = true;
                continue;
            }
            var legacyValue = FromTypeName(legacyType.TypeName, legacyType.IsValueType);
            var relation = CompareValue(pair.Value, legacyValue);
            if (relation == ValueRelation.Different)
                differences.Add(new LegacyStateDifference(LegacyStateDifferenceKind.LocalValue,
                    $"local v{pair.Key.Index} formal={pair.Value} legacy={legacyValue}"));
            else if (relation == ValueRelation.Compatible)
                usedUnknown = true;
        }

        return Result(differences.Count > 0
            ? LegacyComparisonKind.Different
            : usedUnknown ? LegacyComparisonKind.Compatible : LegacyComparisonKind.Equivalent);

        BlockLegacyComparison Result(LegacyComparisonKind kind) =>
            new(block.Id, block.EndInstructionIndex, kind, differences,
                LegacyDifferenceClassification.None);
    }

    private enum ValueRelation
    {
        Equivalent,
        Compatible,
        Different,
    }

    private static ValueRelation CompareValue(AbstractValue formal, AbstractValue legacy)
    {
        if (formal.Kind == AbstractValueKind.Unknown || legacy.Kind == AbstractValueKind.Unknown)
            return ValueRelation.Compatible;
        if (formal.Kind != legacy.Kind)
            return ValueRelation.Different;

        if (formal.Kind == AbstractValueKind.Reference)
        {
            if (formal.Nullability == AbstractNullability.Null
                && legacy.Nullability is AbstractNullability.NonNull)
                return ValueRelation.Different;
            if (formal.Nullability == AbstractNullability.NonNull
                && legacy.Nullability is AbstractNullability.Null)
                return ValueRelation.Different;
        }

        bool typeEqual = string.Equals(formal.ExactType, legacy.ExactType,
            StringComparison.Ordinal);
        bool typeCompatible = typeEqual || formal.ExactType is null || legacy.ExactType is null
            || formal.ExactType == "System.Object" || legacy.ExactType == "System.Object"
            || IsCliStackEquivalent(formal.ExactType, legacy.ExactType);
        if (!typeCompatible)
            return ValueRelation.Different;

        bool nullEqual = formal.Nullability == legacy.Nullability;
        return typeEqual && nullEqual
            ? ValueRelation.Equivalent
            : ValueRelation.Compatible;
    }

    private static AbstractValue FromLegacy(LegacyStackValueSnapshot value)
    {
        if (value.ManagedPointer)
            return AbstractValue.ManagedPointer(value.TypeName);
        if (value.KnownNull)
            return AbstractValue.Null;
        return FromTypeName(value.TypeName, value.IsValueType);
    }

    private static AbstractValue FromTypeName(string? typeName, bool isValueType) => typeName switch
    {
        null => AbstractValue.Unknown,
        "System.Boolean" or "System.Byte" or "System.SByte" or "System.Char"
            or "System.Int16" or "System.UInt16" or "System.Int32" or "System.UInt32" =>
            AbstractValue.Int32,
        "System.Int64" or "System.UInt64" => AbstractValue.Int64,
        "System.IntPtr" or "System.UIntPtr" => AbstractValue.NativeInt,
        "System.Single" => AbstractValue.Float32,
        "System.Double" => AbstractValue.Float64,
        _ when isValueType => AbstractValue.ValueType(typeName),
        _ => AbstractValue.Reference(typeName),
    };

    private static bool IsCliStackEquivalent(string left, string right)
    {
        if (left == right)
            return true;
        return IsInt32StackType(left) && IsInt32StackType(right)
            || IsInt64StackType(left) && IsInt64StackType(right)
            || IsNativeIntStackType(left) && IsNativeIntStackType(right);
    }

    private static bool IsInt32StackType(string name) => name is
        "System.Boolean" or "System.Byte" or "System.SByte" or "System.Char"
        or "System.Int16" or "System.UInt16" or "System.Int32" or "System.UInt32";

    private static bool IsInt64StackType(string name) =>
        name is "System.Int64" or "System.UInt64";

    private static bool IsNativeIntStackType(string name) =>
        name is "System.IntPtr" or "System.UIntPtr";
}
