namespace AgileDevirtualizer.Analysis;

internal sealed record DispatcherRewriteStatistics(
    int EliminatedDispatchers,
    int RedirectedTransitions,
    int RemovedStateInstructions);

internal sealed class DispatcherRewriteResult
{
    public DispatcherRewriteResult(
        DispatcherEliminationResult plan,
        SemanticControlFlowGraph graph,
        DispatcherRewriteStatistics statistics)
    {
        Plan = plan;
        Graph = graph;
        Statistics = statistics;
    }

    public DispatcherEliminationResult Plan { get; }
    public SemanticControlFlowGraph Graph { get; }
    public DispatcherRewriteStatistics Statistics { get; }
}

internal static class DispatcherGraphRewriter
{
    public static DispatcherRewriteResult Rewrite(DispatcherEliminationResult plan)
    {
        var ssa = plan.Simplification.DeadCode.Sccp.Graph;
        var source = ssa.Source;
        var transitions = plan.Eliminations.SelectMany(elimination =>
            elimination.Dispatcher.Transitions).ToDictionary(
                transition => transition.PredecessorBlockId);
        var slices = plan.Eliminations.SelectMany(elimination => elimination.StateSlices)
            .ToDictionary(slice => slice.PredecessorBlockId);
        var blocks = new BasicBlock[source.Blocks.Count];

        foreach (var block in source.Blocks)
        {
            if (!transitions.TryGetValue(block.Id, out var transition))
            {
                blocks[block.Id] = block;
                continue;
            }
            var ssaBlock = ssa.Blocks[block.Id];
            var removable = slices[block.Id].RemovableInstructionIds;
            var operations = ssaBlock.Instructions
                .Where(instruction => !removable.Contains(instruction.Id))
                .Select(instruction => instruction.Operation).ToArray();
            int targetInstruction = source.Blocks[transition.SelectedEdge.TargetBlockId]
                .StartInstructionIndex;
            var terminator = new SemanticTerminator(SemanticTerminatorKind.Branch,
                [targetInstruction], "dispatcher transition eliminated");
            blocks[block.Id] = block with { Operations = operations, Terminator = terminator };
        }

        var byIncoming = plan.Eliminations.SelectMany(elimination =>
                elimination.Dispatcher.Transitions)
            .ToDictionary(transition => transition.IncomingEdge);
        var edges = new List<ControlFlowEdge>();
        foreach (var edge in source.Edges)
        {
            if (!byIncoming.TryGetValue(edge, out var transition))
            {
                edges.Add(edge);
                continue;
            }
            edges.Add(new ControlFlowEdge(edge.SourceBlockId,
                transition.SelectedEdge.TargetBlockId, ControlFlowEdgeKind.Branch));
        }

        var graph = new SemanticControlFlowGraph(source.InstructionCount, blocks, edges,
            source.ExceptionRegions);
        int removed = slices.Values.Sum(slice => slice.RemovableInstructionIds.Count);
        return new DispatcherRewriteResult(plan, graph,
            new DispatcherRewriteStatistics(plan.Eliminations.Count,
                transitions.Count, removed));
    }
}
