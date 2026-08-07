using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// A phi congruence class: every value connected through a needed phi's result/input relation.
/// All members share one exactly typed storage slot, which makes the phi itself disappear.
/// </summary>
internal sealed record SsaPhiClass(
    int Id,
    TypeSignature Type,
    IReadOnlySet<int> Members,
    SsaVariableSlot? ReusedVariable)
{
    public override string ToString() => $"C{Id}:{Type.FullName}"
        + (ReusedVariable is { } variable ? $"@{variable}" : string.Empty)
        + $"[{string.Join(",", Members.Order().Select(id => $"%{id}"))}]";
}

internal enum SsaClassStoreSource
{
    /// <summary>The class slot receives a value that is already on the evaluation stack.</summary>
    StackValue,

    /// <summary>The class slot receives a folded constant.</summary>
    Constant,

    /// <summary>The class slot receives an initial local or argument slot.</summary>
    InitialVariable,
}

internal sealed record SsaClassStore(
    int ClassId,
    SsaClassStoreSource Source,
    int ValueId,
    object? Constant = null,
    SsaVariableSlot? Variable = null);

/// <summary>
/// One materialization root inside a block. A root is emitted at its original ordinal, so the
/// relative order of every observable or potentially throwing operation is preserved.
/// </summary>
internal sealed record SsaPhiBlockRoot(
    int InstructionId,
    int Ordinal,
    int? SpillValueId,
    int? ClassId,
    bool DiscardResult);

internal sealed record SsaPhiBlockPlan(
    int BlockId,
    IReadOnlyList<int> EntryClassIds,
    IReadOnlyList<SsaPhiBlockRoot> Roots,
    IReadOnlyList<SsaClassStore> ExitStores,
    IReadOnlyList<int> PlannedInstructionIds);

internal sealed record SsaPhiLoweringPlan(
    DeadCodeResult DeadCode,
    SsaCilTypeResult Types,
    bool Eligible,
    string Reason,
    IReadOnlyList<int> BlockOrder,
    IReadOnlyList<SsaPhiClass> Classes,
    IReadOnlyDictionary<int, int> ValueClass,
    IReadOnlyDictionary<int, TypeSignature> SpillTypes,
    IReadOnlyList<SsaClassStore> EntryStores,
    IReadOnlyDictionary<int, SsaPhiBlockPlan> Blocks)
{
    public static SsaPhiLoweringPlan Reject(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        string reason) => new(deadCode, types, false, reason, [], [],
            new Dictionary<int, int>(), new Dictionary<int, TypeSignature>(), [],
            new Dictionary<int, SsaPhiBlockPlan>());

    public int TotalRoots => Blocks.Values.Sum(block => block.Roots.Count);

    public int TotalClassStores => EntryStores.Count
        + Blocks.Values.Sum(block => block.ExitStores.Count)
        + Blocks.Values.Sum(block => block.Roots.Count(root => root.ClassId is not null));

    public override string ToString() => Eligible
        ? $"blocks={Blocks.Count} classes={Classes.Count} spills={SpillTypes.Count} "
            + $"roots={TotalRoots} classStores={TotalClassStores}"
        : $"rejected: {Reason}";
}
