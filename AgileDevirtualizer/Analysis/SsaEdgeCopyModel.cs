using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal enum SsaEdgeCopyPlacement
{
    MethodEntry,
    SourceExit,
    TargetEntry,
    SplitBlock,
}

/// <summary>A typed parallel assignment implementing one live phi input.</summary>
internal sealed record SsaTypedPhiCopy(
    int PhiValueId,
    int SourceValueId,
    TypeSignature Type);

/// <summary>
/// Copies associated with one executable CFG edge. Critical edges always receive a synthetic
/// block; non-critical copies are placed at an unambiguous source exit or target entry.
/// </summary>
internal sealed record SsaEdgeCopy(
    ControlFlowEdge? Edge,
    SsaEdgeCopyPlacement Placement,
    IReadOnlyList<SsaTypedPhiCopy> Copies)
{
    public int? SourceBlockId => Edge?.SourceBlockId;
    public int TargetBlockId => Edge?.TargetBlockId ?? 0;
}

internal sealed record SsaEdgeCopyPlan(
    DeadCodeResult DeadCode,
    SsaCilTypeResult Types,
    bool Eligible,
    string Reason,
    IReadOnlyList<int> BlockOrder,
    IReadOnlyDictionary<int, TypeSignature> PhiTypes,
    IReadOnlyDictionary<int, TypeSignature> OperationSpillTypes,
    IReadOnlyList<SsaEdgeCopy> EdgeCopies)
{
    public static SsaEdgeCopyPlan Reject(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        string reason) => new(deadCode, types, false, reason, [],
            new Dictionary<int, TypeSignature>(),
            new Dictionary<int, TypeSignature>(), []);

    public int CriticalEdges => EdgeCopies.Count(copy =>
        copy.Placement == SsaEdgeCopyPlacement.SplitBlock);

    public int TotalCopies => EdgeCopies.Sum(edge => edge.Copies.Count);

    public override string ToString() => Eligible
        ? $"blocks={BlockOrder.Count} phis={PhiTypes.Count} copies={TotalCopies} "
            + $"critical={CriticalEdges} spills={OperationSpillTypes.Count}"
        : $"rejected: {Reason}";
}
