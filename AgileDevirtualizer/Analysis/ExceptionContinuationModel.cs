namespace AgileDevirtualizer.Analysis;

internal sealed record LeaveContinuation(
    int Id,
    ControlFlowEdge Edge,
    IReadOnlyList<int> FinallyRegionIds,
    int FinalTargetBlockId,
    RegionTransition Transition);

internal sealed record RethrowContinuation(
    int SourceBlockId,
    int? ActiveCatchRegionId,
    bool ContinuesDynamicExceptionSearch);

internal sealed record EndFinallyContinuation(
    int SourceBlockId,
    int? HandlerRegionId,
    ExceptionClauseKind HandlerKind,
    IReadOnlyList<int> ResumableLeaveIds,
    bool ContinuesExceptionUnwind);

internal sealed record EndFilterContinuation(
    int SourceBlockId,
    int? FilterRegionId,
    int? AcceptedHandlerBlockId,
    bool RejectedContinuesExceptionSearch);

internal sealed class ExceptionContinuationModel
{
    public ExceptionContinuationModel(
        SsaGraph graph,
        IReadOnlyList<LeaveContinuation> leaves,
        IReadOnlyList<RethrowContinuation> rethrows,
        IReadOnlyList<EndFinallyContinuation> endFinallys,
        IReadOnlyList<EndFilterContinuation> endFilters)
    {
        Graph = graph;
        Leaves = leaves;
        Rethrows = rethrows;
        EndFinallys = endFinallys;
        EndFilters = endFilters;
    }

    public SsaGraph Graph { get; }
    public IReadOnlyList<LeaveContinuation> Leaves { get; }
    public IReadOnlyList<RethrowContinuation> Rethrows { get; }
    public IReadOnlyList<EndFinallyContinuation> EndFinallys { get; }
    public IReadOnlyList<EndFilterContinuation> EndFilters { get; }
}

/// <summary>Builds explicit EH continuation semantics without rewriting the CFG or emitted CIL.</summary>
internal static class ExceptionContinuationModelBuilder
{
    public static ExceptionContinuationModel Build(SsaGraph graph)
    {
        var leaves = BuildLeaves(graph);
        var rethrows = BuildRethrows(graph);
        var endFilters = BuildEndFilters(graph);
        var endFinallys = BuildEndFinallys(graph, leaves);
        return new ExceptionContinuationModel(graph, leaves, rethrows, endFinallys, endFilters);
    }

    private static IReadOnlyList<LeaveContinuation> BuildLeaves(SsaGraph graph)
    {
        var result = new List<LeaveContinuation>();
        foreach (var edge in graph.Source.Edges.Where(edge =>
            edge.Kind == ControlFlowEdgeKind.Leave
            && graph.Blocks[edge.SourceBlockId].Reachable))
        {
            var transition = RegionTransitionClassifier.Classify(graph.Source, edge);
            var sourcePath = graph.Source.Blocks[edge.SourceBlockId].RegionPath;
            var targetPath = graph.Source.Blocks[edge.TargetBlockId].RegionPath;
            var finallyRegions = sourcePath.Frames
                .Where(frame => frame.Zone == RegionZone.Try
                    && frame.ClauseKind == ExceptionClauseKind.Finally
                    && !targetPath.Frames.Contains(frame))
                .Reverse()
                .Select(frame => frame.RegionId)
                .Distinct()
                .ToArray();
            result.Add(new LeaveContinuation(result.Count, edge, finallyRegions,
                edge.TargetBlockId, transition));
        }
        return result;
    }

    private static IReadOnlyList<RethrowContinuation> BuildRethrows(SsaGraph graph) =>
        graph.Blocks.Where(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.Rethrow)
        .Select(block =>
        {
            var sourcePath = graph.Source.Blocks[block.Id].RegionPath;
            int? activeCatch = sourcePath.Frames.Reverse().FirstOrDefault(frame =>
                frame.Zone == RegionZone.Handler
                && frame.ClauseKind is ExceptionClauseKind.Catch
                    or ExceptionClauseKind.Filter) is { } frame
                && frame.Zone == RegionZone.Handler ? frame.RegionId : null;
            return new RethrowContinuation(block.Id, activeCatch,
                ContinuesDynamicExceptionSearch: true);
        }).ToArray();

    private static IReadOnlyList<EndFinallyContinuation> BuildEndFinallys(
        SsaGraph graph,
        IReadOnlyList<LeaveContinuation> leaves) =>
        graph.Blocks.Where(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.EndFinally)
        .Select(block =>
        {
            var owner = graph.Source.Blocks[block.Id].RegionPath.Frames.Reverse()
                .FirstOrDefault(frame => frame.Zone == RegionZone.Handler
                    && frame.ClauseKind is ExceptionClauseKind.Finally
                        or ExceptionClauseKind.Fault);
            int? regionId = owner.Zone == RegionZone.Handler ? owner.RegionId : null;
            var resumable = regionId is { } id
                ? leaves.Where(leave => leave.FinallyRegionIds.Contains(id))
                    .Select(leave => leave.Id).ToArray()
                : [];
            return new EndFinallyContinuation(block.Id, regionId,
                regionId is null ? ExceptionClauseKind.Unknown : owner.ClauseKind,
                resumable, ContinuesExceptionUnwind: true);
        }).ToArray();

    private static IReadOnlyList<EndFilterContinuation> BuildEndFilters(SsaGraph graph) =>
        graph.Blocks.Where(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.EndFilter)
        .Select(block =>
        {
            var owner = graph.Source.Blocks[block.Id].RegionPath.Frames.Reverse()
                .FirstOrDefault(frame => frame.Zone == RegionZone.Filter
                    && frame.ClauseKind == ExceptionClauseKind.Filter);
            int? regionId = owner.Zone == RegionZone.Filter ? owner.RegionId : null;
            int? accepted = graph.Source.Outgoing(graph.Source.Blocks[block.Id])
                .SingleOrDefault(edge => edge.Kind == ControlFlowEdgeKind.ExceptionFilterHandler
                    && edge.ExceptionRegionId == regionId)?.TargetBlockId;
            return new EndFilterContinuation(block.Id, regionId, accepted,
                RejectedContinuesExceptionSearch: true);
        }).ToArray();
}
