using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaShadowPlan(
    DeadCodeResult DeadCode,
    SsaCilTypeResult Types,
    ExceptionEntryModel Entries,
    ExceptionContinuationModel Continuations,
    RegionPhiCopyLegalityPlan Legality,
    bool Eligible,
    string Reason,
    IReadOnlyList<int> BlockOrder,
    IReadOnlySet<int> EmissionInstructionIds,
    IReadOnlySet<int> EmissionValueIds,
    IReadOnlyDictionary<int, object?> ConstantValues,
    IReadOnlyDictionary<int, SsaVariableSlot> VariablePhiSlots,
    IReadOnlyDictionary<int, TypeSignature> StackPhiTypes,
    IReadOnlyDictionary<int, TypeSignature> ExceptionObjectTypes,
    IReadOnlyDictionary<int, TypeSignature> OperationSpillTypes,
    IReadOnlyDictionary<int, EhFunctionPointerRematerialization> FunctionPointers,
    IReadOnlyList<SsaEdgeCopy> EdgeCopies)
{
    public static EhSsaShadowPlan Reject(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        ExceptionEntryModel entries,
        ExceptionContinuationModel continuations,
        RegionPhiCopyLegalityPlan legality,
        string reason) => new(deadCode, types, entries, continuations, legality,
            false, reason, [], new HashSet<int>(), new HashSet<int>(),
            new Dictionary<int, object?>(), new Dictionary<int, SsaVariableSlot>(),
            new Dictionary<int, TypeSignature>(), new Dictionary<int, TypeSignature>(),
            new Dictionary<int, TypeSignature>(),
            new Dictionary<int, EhFunctionPointerRematerialization>(), []);

    public int TotalCopies => EdgeCopies.Sum(edge => edge.Copies.Count);
}
