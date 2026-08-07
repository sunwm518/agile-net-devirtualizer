namespace AgileDevirtualizer.Analysis;

internal enum ExceptionClauseKind
{
    Catch,
    Filter,
    Finally,
    Fault,
    Unknown,
}

internal enum RegionZone
{
    Try,
    Filter,
    Handler,
}

internal sealed record ExceptionRegion(
    int Id,
    ExceptionClauseKind ClauseKind,
    int TryStart,
    int TryEnd,
    int HandlerStart,
    int HandlerEnd,
    int? CatchTypeToken,
    int? FilterStart)
{
    public int FullStart => Math.Min(Math.Min(TryStart, HandlerStart), FilterStart ?? int.MaxValue);
    public int FullEnd => Math.Max(TryEnd, HandlerEnd);

    public int ExceptionDispatchStart => FilterStart ?? HandlerStart;
}

internal readonly record struct RegionFrame(
    int RegionId,
    ExceptionClauseKind ClauseKind,
    RegionZone Zone)
{
    public override string ToString() => $"EH{RegionId}.{Zone}({ClauseKind})";
}

/// <summary>
/// Ordered outer-to-inner exception-region ownership for one VM instruction/basic block.
/// </summary>
internal sealed record RegionPath(IReadOnlyList<RegionFrame> Frames)
{
    public static RegionPath Outside { get; } = new(Array.Empty<RegionFrame>());

    public bool IsOutside => Frames.Count == 0;

    public bool ExitsTo(RegionPath target)
    {
        int shared = 0;
        while (shared < Frames.Count && shared < target.Frames.Count
            && Frames[shared] == target.Frames[shared])
            shared++;
        return shared < Frames.Count;
    }

    public override string ToString() =>
        Frames.Count == 0 ? "outside" : string.Join(" > ", Frames);
}
