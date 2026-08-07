namespace AgileDevirtualizer.Analysis;

internal enum RegionTransitionKind
{
    SameRegion,
    EnterTry,
    ExitViaLeave,
    ExitAndEnterTryViaLeave,
    ExceptionDispatch,
    Invalid,
}

[Flags]
internal enum RegionCopyPlacement
{
    None = 0,
    MethodEntry = 1,
    SourceExit = 2,
    TargetEntry = 4,
    SplitBlock = 8,
}

internal sealed record RegionTransition(
    RegionTransitionKind Kind,
    RegionPath Source,
    RegionPath Target,
    RegionCopyPlacement AllowedPlacements,
    RegionPath? SplitBlockPath,
    bool RequiresFinallyUnwind,
    string Reason)
{
    public bool Valid => Kind != RegionTransitionKind.Invalid;
}

/// <summary>ECMA-335 region rules for one formal CFG edge.</summary>
internal static class RegionTransitionClassifier
{
    private const RegionCopyPlacement NormalPlacements = RegionCopyPlacement.SourceExit
        | RegionCopyPlacement.TargetEntry | RegionCopyPlacement.SplitBlock;

    public static RegionTransition Classify(
        SemanticControlFlowGraph graph,
        ControlFlowEdge edge)
    {
        var source = graph.Blocks[edge.SourceBlockId];
        var target = graph.Blocks[edge.TargetBlockId];
        if (ControlFlowEdgeSemantics.IsException(edge.Kind))
            return ExceptionDispatch(graph, edge, source, target);

        var sourceFrames = source.RegionPath.Frames;
        var targetFrames = target.RegionPath.Frames;
        int shared = 0;
        while (shared < sourceFrames.Count && shared < targetFrames.Count
            && sourceFrames[shared] == targetFrames[shared])
            shared++;
        var removed = sourceFrames.Skip(shared).ToArray();
        var added = targetFrames.Skip(shared).ToArray();

        if (added.Any(frame => frame.Zone is RegionZone.Filter or RegionZone.Handler))
            return Invalid(source, target, "normal control flow cannot enter a filter or handler");
        if (removed.Length > 0 && edge.Kind != ControlFlowEdgeKind.Leave)
            return Invalid(source, target, "control flow exits an EH region without leave");
        if (edge.Kind == ControlFlowEdgeKind.Leave
            && removed.Any(frame => frame.Zone == RegionZone.Filter
                || frame.Zone == RegionZone.Handler
                && frame.ClauseKind is ExceptionClauseKind.Finally or ExceptionClauseKind.Fault))
            return Invalid(source, target, "leave cannot exit filter/finally/fault code");

        foreach (var frame in added.Where(frame => frame.Zone == RegionZone.Try))
        {
            var region = graph.ExceptionRegions.Single(candidate => candidate.Id == frame.RegionId);
            bool associatedHandlerReturn = edge.Kind == ControlFlowEdgeKind.Leave
                && sourceFrames.Any(sourceFrame => sourceFrame.RegionId == frame.RegionId
                    && sourceFrame.Zone == RegionZone.Handler
                    && sourceFrame.ClauseKind is ExceptionClauseKind.Catch
                        or ExceptionClauseKind.Filter);
            if (target.StartInstructionIndex != region.TryStart && !associatedHandlerReturn)
                return Invalid(source, target,
                    $"control flow enters EH{frame.RegionId}.Try below its first instruction");
        }

        bool finallyUnwind = edge.Kind == ControlFlowEdgeKind.Leave
            && removed.Any(frame => frame.Zone == RegionZone.Try
                && frame.ClauseKind == ExceptionClauseKind.Finally);
        var kind = (removed.Length > 0, added.Length > 0) switch
        {
            (false, false) => RegionTransitionKind.SameRegion,
            (false, true) => RegionTransitionKind.EnterTry,
            (true, false) => RegionTransitionKind.ExitViaLeave,
            _ => RegionTransitionKind.ExitAndEnterTryViaLeave,
        };
        return new RegionTransition(kind, source.RegionPath, target.RegionPath,
            NormalPlacements, target.RegionPath, finallyUnwind,
            finallyUnwind ? "copy timing depends on finally unwind"
                : "normal region transition is copy-safe");
    }

    private static RegionTransition ExceptionDispatch(
        SemanticControlFlowGraph graph,
        ControlFlowEdge edge,
        BasicBlock source,
        BasicBlock target)
    {
        if (edge.ExceptionRegionId is not { } regionId
            || graph.ExceptionRegions.SingleOrDefault(region => region.Id == regionId) is not { } region)
            return Invalid(source, target, "exception edge has no matching EH region");
        var expectedZone = edge.Kind == ControlFlowEdgeKind.ExceptionFilter
            ? RegionZone.Filter : RegionZone.Handler;
        if (!target.RegionPath.Frames.Any(frame => frame.RegionId == regionId
            && frame.ClauseKind == region.ClauseKind && frame.Zone == expectedZone))
            return Invalid(source, target,
                $"{edge.Kind} does not target EH{regionId}.{expectedZone}");
        var expectedSourceZone = edge.Kind == ControlFlowEdgeKind.ExceptionFilterHandler
            ? RegionZone.Filter : RegionZone.Try;
        if (!source.RegionPath.Frames.Any(frame => frame.RegionId == regionId
            && frame.Zone == expectedSourceZone))
            return Invalid(source, target,
                $"{edge.Kind} does not originate in EH{regionId}.{expectedSourceZone}");
        return new RegionTransition(RegionTransitionKind.ExceptionDispatch,
            source.RegionPath, target.RegionPath, RegionCopyPlacement.None, null,
            RequiresFinallyUnwind: false, "CLI exception dispatch; emitted edge copies are forbidden");
    }

    private static RegionTransition Invalid(
        BasicBlock source,
        BasicBlock target,
        string reason) => new(RegionTransitionKind.Invalid, source.RegionPath,
            target.RegionPath, RegionCopyPlacement.None, null, false, reason);
}
