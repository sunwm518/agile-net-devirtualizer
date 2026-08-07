namespace AgileDevirtualizer.Lift;

/// <summary>
/// Read-only projection of the legacy interpreter state used by observational analysis. The stack
/// is normalized to bottom-to-top order so it can be compared directly with <c>AbstractState</c>.
/// </summary>
internal sealed record LegacyStackValueSnapshot(
    string? TypeName,
    bool IsValueType,
    bool ManagedPointer,
    bool KnownNull);

internal sealed record LegacyLocalValueSnapshot(
    string? TypeName,
    bool IsValueType);

internal sealed record LegacyStateSnapshot(
    int VmInstructionIndex,
    IReadOnlyList<LegacyStackValueSnapshot> StackBottomToTop,
    IReadOnlyDictionary<int, LegacyLocalValueSnapshot> KnownLocalTypes);
