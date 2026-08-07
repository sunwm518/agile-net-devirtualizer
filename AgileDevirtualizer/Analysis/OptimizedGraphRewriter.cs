namespace AgileDevirtualizer.Analysis;

internal sealed record OptimizedGraphRewriteStatistics(
    int EliminatedDispatchers,
    int FoldedConstantBranches,
    int RedirectedTransitions,
    int RemovedSemanticInstructions);

internal sealed class OptimizedGraphRewriteResult
{
    public OptimizedGraphRewriteResult(
        DispatcherEliminationResult dispatchers,
        ConstantBranchEliminationResult branches,
        SemanticControlFlowGraph graph,
        OptimizedGraphRewriteStatistics statistics)
    {
        Dispatchers = dispatchers;
        Branches = branches;
        Graph = graph;
        Statistics = statistics;
    }

    public DispatcherEliminationResult Dispatchers { get; }
    public ConstantBranchEliminationResult Branches { get; }
    public SemanticControlFlowGraph Graph { get; }
    public OptimizedGraphRewriteStatistics Statistics { get; }
}

internal static class OptimizedGraphRewriter
{
    public static OptimizedGraphRewriteResult Rewrite(
        DispatcherEliminationResult dispatchers,
        ConstantBranchEliminationResult branches)
    {
        if (!ReferenceEquals(dispatchers.Simplification, branches.Simplification))
            throw new ArgumentException("rewrite plans belong to different simplification results");
        var ssa = dispatchers.Simplification.DeadCode.Sccp.Graph;
        var source = ssa.Source;
        var dispatcherTransitions = dispatchers.Eliminations
            .SelectMany(elimination => elimination.Dispatcher.Transitions)
            .ToDictionary(transition => transition.PredecessorBlockId);
        var folded = branches.Eliminations.ToDictionary(
            elimination => elimination.Terminator.BlockId);
        if (dispatcherTransitions.Keys.Intersect(folded.Keys).Any())
            throw new InvalidOperationException(
                "a block cannot be both a state transition and a folded conditional");

        var removals = new Dictionary<int, HashSet<int>>();
        foreach (var slice in dispatchers.Eliminations.SelectMany(item => item.StateSlices))
            AddRemovals(slice.PredecessorBlockId, slice.RemovableInstructionIds);
        foreach (var elimination in branches.Eliminations)
            foreach (var pair in elimination.RemovableInstructionsByBlock)
                AddRemovals(pair.Key, pair.Value);

        var blocks = new BasicBlock[source.Blocks.Count];
        foreach (var block in source.Blocks)
        {
            bool isTransition = dispatcherTransitions.TryGetValue(block.Id, out var transition);
            bool isFolded = folded.TryGetValue(block.Id, out var branch);
            bool hasRemovals = removals.TryGetValue(block.Id, out var blockRemovals);
            if (!isTransition && !isFolded && !hasRemovals)
            {
                blocks[block.Id] = block;
                continue;
            }
            var operations = ssa.Blocks[block.Id].Instructions
                .Where(instruction => blockRemovals is null
                    || !blockRemovals.Contains(instruction.Id))
                .Select(instruction => instruction.Operation).ToArray();
            if (!isTransition && !isFolded)
            {
                blocks[block.Id] = block with { Operations = operations };
                continue;
            }
            int targetId = isTransition
                ? transition!.SelectedEdge.TargetBlockId
                : branch!.Terminator.SelectedEdge.TargetBlockId;
            var terminator = new SemanticTerminator(SemanticTerminatorKind.Branch,
                [source.Blocks[targetId].StartInstructionIndex],
                isTransition ? "dispatcher transition eliminated" : "constant branch folded");
            blocks[block.Id] = block with { Operations = operations, Terminator = terminator };
        }

        var transitionByEdge = dispatchers.Eliminations
            .SelectMany(elimination => elimination.Dispatcher.Transitions)
            .ToDictionary(transition => transition.IncomingEdge);
        var edges = new List<ControlFlowEdge>();
        foreach (var edge in source.Edges)
        {
            if (transitionByEdge.TryGetValue(edge, out var transition))
            {
                edges.Add(new ControlFlowEdge(edge.SourceBlockId,
                    transition.SelectedEdge.TargetBlockId, ControlFlowEdgeKind.Branch));
                continue;
            }
            if (folded.TryGetValue(edge.SourceBlockId, out var branch)
                && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind))
            {
                if (edge == branch.Terminator.SelectedEdge)
                    edges.Add(new ControlFlowEdge(edge.SourceBlockId, edge.TargetBlockId,
                        ControlFlowEdgeKind.Branch));
                continue;
            }
            edges.Add(edge);
        }

        var graph = new SemanticControlFlowGraph(source.InstructionCount, blocks, edges,
            source.ExceptionRegions);
        return new OptimizedGraphRewriteResult(dispatchers, branches, graph,
            new OptimizedGraphRewriteStatistics(dispatchers.Eliminations.Count,
                branches.Eliminations.Count, dispatcherTransitions.Count,
                removals.Values.Sum(ids => ids.Count)));

        void AddRemovals(int blockId, IEnumerable<int> instructionIds)
        {
            if (!removals.TryGetValue(blockId, out var ids))
                removals[blockId] = ids = [];
            ids.UnionWith(instructionIds);
        }
    }
}
