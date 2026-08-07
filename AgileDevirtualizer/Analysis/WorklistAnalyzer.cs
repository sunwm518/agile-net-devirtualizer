namespace AgileDevirtualizer.Analysis;

internal sealed record BlockState(
    AbstractState Entry,
    AbstractState Exit,
    int ProcessCount);

internal sealed record WorklistAnalysisResult(
    SemanticControlFlowGraph Graph,
    IReadOnlyDictionary<int, BlockState> Blocks,
    bool Converged,
    int Iterations,
    IReadOnlyList<string> Diagnostics);

/// <summary>Forward finite-lattice analysis over the formal observational CFG.</summary>
internal static class WorklistAnalyzer
{
    private const int MaximumIterations = 100_000;

    public static WorklistAnalysisResult Analyze(SemanticControlFlowGraph graph)
    {
        if (graph.Blocks.Count == 0)
            return new WorklistAnalysisResult(graph, new Dictionary<int, BlockState>(),
                true, 0, Array.Empty<string>());

        var entries = graph.Blocks.ToDictionary(block => block.Id,
            block => AbstractState.Unreachable(block.RegionPath));
        var exits = graph.Blocks.ToDictionary(block => block.Id,
            block => AbstractState.Unreachable(block.RegionPath));
        var processCounts = graph.Blocks.ToDictionary(block => block.Id, _ => 0);
        entries[0] = AbstractState.Entry(graph.Blocks[0].RegionPath);
        var queue = new Queue<int>();
        var queued = new HashSet<int>();
        queue.Enqueue(0);
        queued.Add(0);
        int iterations = 0;

        while (queue.Count > 0 && iterations < MaximumIterations)
        {
            int blockId = queue.Dequeue();
            queued.Remove(blockId);
            iterations++;
            processCounts[blockId]++;
            var block = graph.Blocks[blockId];
            var exit = SemanticTransfer.Transfer(block, entries[blockId]);
            exits[blockId] = exit;

            foreach (var edge in SsaControlFlow.Outgoing(graph, block))
            {
                var target = graph.Blocks[edge.TargetBlockId];
                var incoming = StateForEdge(exit, edge, target.RegionPath);
                var joined = AbstractState.Join(entries[target.Id], incoming, target.RegionPath);
                if (entries[target.Id].LatticeEquals(joined))
                    continue;
                entries[target.Id] = joined;
                if (queued.Add(target.Id))
                    queue.Enqueue(target.Id);
            }
        }

        bool converged = queue.Count == 0;
        var diagnostics = new List<string>();
        if (!converged)
            diagnostics.Add($"worklist exceeded {MaximumIterations} iterations");
        foreach (var block in graph.Blocks)
        {
            if (!entries[block.Id].Reachable)
                diagnostics.Add($"B{block.Id} is unreachable in the observational graph");
            if (entries[block.Id].Stack is null)
                diagnostics.Add($"B{block.Id} has a conflicting/unknown entry stack shape");
        }

        var states = graph.Blocks.ToDictionary(block => block.Id,
            block => new BlockState(entries[block.Id], exits[block.Id], processCounts[block.Id]));
        return new WorklistAnalysisResult(graph, states, converged, iterations, diagnostics);
    }

    private static AbstractState StateForEdge(
        AbstractState source,
        ControlFlowEdge edge,
        RegionPath targetPath)
    {
        if (ControlFlowEdgeSemantics.SeedsExceptionObject(edge.Kind))
        {
            return new AbstractState(true,
                [AbstractValue.Reference("System.Exception", nonNull: true)],
                source.Locals, targetPath, source.IsImprecise);
        }
        if (edge.Kind is ControlFlowEdgeKind.ExceptionFinally or ControlFlowEdgeKind.ExceptionFault)
        {
            return new AbstractState(true, Array.Empty<AbstractValue>(),
                source.Locals, targetPath, source.IsImprecise);
        }
        return source.WithRegion(targetPath);
    }
}
