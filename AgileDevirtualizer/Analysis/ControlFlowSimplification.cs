namespace AgileDevirtualizer.Analysis;

internal sealed record FoldedTerminatorPlan(
    int BlockId,
    SemanticTerminatorKind OriginalKind,
    ControlFlowEdge SelectedEdge,
    SccpTerminatorDecision Decision);

internal sealed record TrivialRedirectPlan(
    int BlockId,
    int TargetBlockId,
    IReadOnlyList<int> PredecessorBlockIds);

internal sealed record DispatcherPlan(
    int BlockId,
    int SelectorValueId,
    IReadOnlyDictionary<long, ControlFlowEdge> StateTargets,
    IReadOnlyList<DispatcherTransition> Transitions);

internal sealed record DispatcherTransition(
    int PredecessorBlockId,
    int StateValueId,
    long State,
    ControlFlowEdge IncomingEdge,
    ControlFlowEdge SelectedEdge);

internal sealed record ControlFlowSimplificationStatistics(
    int RetainedBlocks,
    int RemovedBlocks,
    int RetainedEdges,
    int FoldedTerminators,
    int DispatcherBlocks,
    int TrivialRedirects);

internal sealed class ControlFlowSimplificationResult
{
    public ControlFlowSimplificationResult(
        DeadCodeResult deadCode,
        IReadOnlySet<int> retainedBlockIds,
        IReadOnlySet<ControlFlowEdge> retainedEdges,
        IReadOnlyList<FoldedTerminatorPlan> foldedTerminators,
        IReadOnlyList<DispatcherPlan> dispatchers,
        IReadOnlyList<TrivialRedirectPlan> trivialRedirects)
    {
        DeadCode = deadCode;
        RetainedBlockIds = retainedBlockIds;
        RetainedEdges = retainedEdges;
        FoldedTerminators = foldedTerminators;
        Dispatchers = dispatchers;
        TrivialRedirects = trivialRedirects;
    }

    public DeadCodeResult DeadCode { get; }
    public IReadOnlySet<int> RetainedBlockIds { get; }
    public IReadOnlySet<ControlFlowEdge> RetainedEdges { get; }
    public IReadOnlyList<FoldedTerminatorPlan> FoldedTerminators { get; }
    public IReadOnlyList<DispatcherPlan> Dispatchers { get; }
    public IReadOnlySet<int> DispatcherBlockIds =>
        Dispatchers.Select(dispatcher => dispatcher.BlockId).ToHashSet();
    public IReadOnlyList<TrivialRedirectPlan> TrivialRedirects { get; }
}

internal static class ControlFlowSimplifier
{
    public static ControlFlowSimplificationResult Analyze(DeadCodeResult deadCode)
    {
        var sccp = deadCode.Sccp;
        var graph = sccp.Graph;
        var retainedBlocks = sccp.ExecutableBlocks.ToHashSet();
        var retainedEdges = sccp.ExecutableEdges.Where(edge =>
            retainedBlocks.Contains(edge.SourceBlockId)
            && retainedBlocks.Contains(edge.TargetBlockId)).ToHashSet();
        var folded = new List<FoldedTerminatorPlan>();
        var dispatchers = new List<DispatcherPlan>();

        foreach (var block in graph.Blocks.Where(block =>
            block.Reachable && retainedBlocks.Contains(block.Id)))
        {
            if (block.Terminator is not { } terminator)
                continue;
            var normal = NormalOutgoing(graph.Source, block.Id).ToArray();
            var decision = SccpEvaluator.Decide(terminator, sccp.Values);
            if (normal.Length <= 1 || !decision.Known)
                continue;
            var selected = normal.Where(retainedEdges.Contains).ToArray();
            if (selected.Length != 1)
                continue;
            folded.Add(new FoldedTerminatorPlan(block.Id, terminator.Terminator.Kind,
                selected[0], decision));
        }

        foreach (var block in graph.Blocks.Where(block =>
            block.Reachable && retainedBlocks.Contains(block.Id)))
        {
            if (TryBuildDispatcher(block, graph, sccp, retainedEdges, out var dispatcher))
                dispatchers.Add(dispatcher);
        }

        var redirects = graph.Blocks.Where(block =>
                IsTrivialRedirect(block, graph, deadCode, retainedBlocks, retainedEdges))
            .Select(block => new TrivialRedirectPlan(block.Id,
                NormalOutgoing(graph.Source, block.Id).Single(retainedEdges.Contains).TargetBlockId,
                SsaControlFlow.Incoming(graph.Source, graph.Source.Blocks[block.Id])
                    .Where(retainedEdges.Contains).Select(edge => edge.SourceBlockId)
                    .Distinct().OrderBy(id => id).ToArray()))
            .ToArray();

        return new ControlFlowSimplificationResult(deadCode, retainedBlocks, retainedEdges,
            folded, dispatchers, redirects);
    }

    public static ControlFlowSimplificationStatistics Statistics(
        ControlFlowSimplificationResult result) => new(
        result.RetainedBlockIds.Count,
        result.DeadCode.Sccp.Graph.Blocks.Count - result.RetainedBlockIds.Count,
        result.RetainedEdges.Count,
        result.FoldedTerminators.Count,
        result.Dispatchers.Count,
        result.TrivialRedirects.Count);

    internal static IEnumerable<ControlFlowEdge> NormalOutgoing(
        SemanticControlFlowGraph graph,
        int blockId) => SsaControlFlow.Outgoing(graph, graph.Blocks[blockId])
        .Where(edge => !IsExceptionEdge(edge.Kind));

    internal static bool IsTrivialRedirect(
        SsaBlock block,
        SsaGraph graph,
        DeadCodeResult deadCode,
        IReadOnlySet<int> retainedBlocks,
        IReadOnlySet<ControlFlowEdge> retainedEdges)
    {
        if (block.Id == 0 || !retainedBlocks.Contains(block.Id)
            || block.Phis.Count != 0 || block.Terminator is not { Inputs.Count: 0 } terminator
            || terminator.Terminator.Kind is not SemanticTerminatorKind.Branch
                and not SemanticTerminatorKind.FallThrough
            || block.Instructions.Any(instruction =>
                deadCode.LiveInstructionIds.Contains(instruction.Id)))
            return false;

        var source = graph.Source.Blocks[block.Id];
        var outgoing = SsaControlFlow.Outgoing(graph.Source, source)
            .Where(retainedEdges.Contains).ToArray();
        var incoming = SsaControlFlow.Incoming(graph.Source, source)
            .Where(retainedEdges.Contains).ToArray();
        if (outgoing.Length != 1 || incoming.Length == 0
            || outgoing[0].TargetBlockId == block.Id
            || outgoing.Any(edge => IsExceptionEdge(edge.Kind))
            || incoming.Any(edge => IsExceptionEdge(edge.Kind)))
            return false;

        var targetPath = graph.Source.Blocks[outgoing[0].TargetBlockId].RegionPath;
        return SameRegion(source.RegionPath, targetPath)
            && incoming.All(edge => SameRegion(
                graph.Source.Blocks[edge.SourceBlockId].RegionPath, source.RegionPath));
    }

    internal static bool SameRegion(RegionPath left, RegionPath right) =>
        left.Frames.SequenceEqual(right.Frames);

    internal static bool TryBuildDispatcher(
        SsaBlock block,
        SsaGraph graph,
        SccpResult sccp,
        IReadOnlySet<ControlFlowEdge> retainedEdges,
        out DispatcherPlan dispatcher)
    {
        dispatcher = null!;
        if (block.Terminator is not
            { Terminator.Kind: SemanticTerminatorKind.Switch, Inputs.Count: 1 } terminator)
            return false;
        int selectorId = terminator.Inputs[0];
        var phi = block.Phis.SingleOrDefault(candidate => candidate.Result.Id == selectorId);
        if (phi is null)
            return false;

        var states = new HashSet<long>();
        var inputs = new List<(SsaPhiInput Input, long State)>();
        foreach (var input in phi.Inputs.Where(input => input.Kind == SsaPhiInputKind.MethodEntry
            || sccp.ExecutableEdges.Any(edge => edge.SourceBlockId == input.PredecessorBlockId
                && edge.TargetBlockId == block.Id)))
        {
            if (sccp.Values[input.ValueId] is not { Kind: SccpValueKind.Constant } value
                || !TryInt64(value.Constant, out long state))
                return false;
            states.Add(state);
            inputs.Add((input, state));
        }
        if (states.Count < 2)
            return false;

        var normal = NormalOutgoing(graph.Source, block.Id).ToArray();
        var targets = new Dictionary<long, ControlFlowEdge>();
        foreach (long state in states)
        {
            int index = unchecked((int)state);
            var selected = normal.FirstOrDefault(edge => edge.Kind == ControlFlowEdgeKind.SwitchCase
                && edge.SwitchCaseIndex == index)
                ?? normal.SingleOrDefault(edge => edge.Kind == ControlFlowEdgeKind.SwitchDefault);
            if (selected is null || !retainedEdges.Contains(selected))
                return false;
            targets[state] = selected;
        }
        if (!targets.Values.Any(edge => CanReach(
            edge.TargetBlockId, block.Id, graph.Source, retainedEdges)))
            return false;

        var transitions = new List<DispatcherTransition>();
        foreach (var (input, state) in inputs)
        {
            if (input.PredecessorBlockId is not { } predecessor)
                return false;
            var incoming = SsaControlFlow.Incoming(graph.Source,
                    graph.Source.Blocks[block.Id])
                .SingleOrDefault(edge => retainedEdges.Contains(edge)
                    && edge.SourceBlockId == predecessor);
            if (incoming is null)
                return false;
            transitions.Add(new DispatcherTransition(predecessor, input.ValueId, state,
                incoming, targets[state]));
        }

        dispatcher = new DispatcherPlan(block.Id, selectorId, targets, transitions);
        return true;
    }

    private static bool CanReach(
        int start,
        int target,
        SemanticControlFlowGraph graph,
        IReadOnlySet<ControlFlowEdge> retainedEdges)
    {
        var seen = new HashSet<int>();
        var queue = new Queue<int>();
        queue.Enqueue(start);
        while (queue.Count > 0)
        {
            int current = queue.Dequeue();
            if (current == target)
                return true;
            if (!seen.Add(current))
                continue;
            foreach (var edge in SsaControlFlow.Outgoing(graph, graph.Blocks[current])
                .Where(edge => retainedEdges.Contains(edge) && !IsExceptionEdge(edge.Kind)))
                queue.Enqueue(edge.TargetBlockId);
        }
        return false;
    }

    private static bool TryInt64(object? value, out long result)
    {
        switch (value)
        {
            case bool boolean: result = boolean ? 1 : 0; return true;
            case sbyte signed8: result = signed8; return true;
            case byte unsigned8: result = unsigned8; return true;
            case short signed16: result = signed16; return true;
            case ushort unsigned16: result = unsigned16; return true;
            case int signed32: result = signed32; return true;
            case uint unsigned32: result = unsigned32; return true;
            case long signed64: result = signed64; return true;
            case ulong unsigned64: result = unchecked((long)unsigned64); return true;
            case char character: result = character; return true;
        }
        result = 0;
        return false;
    }

    internal static bool IsExceptionEdge(ControlFlowEdgeKind kind) =>
        ControlFlowEdgeSemantics.IsException(kind);
}
