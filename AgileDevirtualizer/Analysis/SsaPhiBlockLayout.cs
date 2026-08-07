namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Block ordering for phi-lowered emission. The order is a reverse post-order in which the
/// conditional fall-through successor is visited last, so it is laid out immediately after its own
/// block and the fall-through branch disappears. The layout also proves that every normal edge
/// leaving an executable block is itself executable, which is what allows the original terminators
/// to be emitted unchanged.
/// </summary>
internal static class SsaPhiBlockLayout
{
    public static bool TryOrder(
        SsaGraph graph,
        SccpResult sccp,
        IReadOnlySet<int> executableIds,
        out IReadOnlyList<int> order,
        out string? error)
    {
        order = [];
        foreach (int blockId in executableIds.Order())
        {
            var normal = SsaControlFlow.Outgoing(graph.Source, graph.Source.Blocks[blockId])
                .Where(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)).ToArray();
            foreach (var edge in normal)
            {
                if (!sccp.ExecutableEdges.Contains(edge))
                {
                    error = $"B{blockId} has an infeasible normal edge to "
                        + $"B{edge.TargetBlockId}; constant branch folding owns this shape";
                    return false;
                }
                if (!executableIds.Contains(edge.TargetBlockId))
                {
                    error = $"B{blockId} branches to non-executable B{edge.TargetBlockId}";
                    return false;
                }
            }
        }

        var seen = new HashSet<int>();
        var postorder = new List<int>();
        Visit(0);
        postorder.Reverse();
        if (postorder.Count != executableIds.Count)
        {
            error = $"block layout reached {postorder.Count} of {executableIds.Count} "
                + "executable blocks";
            return false;
        }
        order = postorder;
        error = null;
        return true;

        void Visit(int blockId)
        {
            if (!executableIds.Contains(blockId) || !seen.Add(blockId))
                return;
            foreach (var edge in SsaControlFlow.Outgoing(graph.Source, graph.Source.Blocks[blockId])
                .Where(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind))
                .Where(edge => executableIds.Contains(edge.TargetBlockId))
                .OrderBy(edge => edge.Kind == ControlFlowEdgeKind.ConditionalFallThrough)
                .ThenByDescending(edge => edge.TargetBlockId))
                Visit(edge.TargetBlockId);
            postorder.Add(blockId);
        }
    }
}
