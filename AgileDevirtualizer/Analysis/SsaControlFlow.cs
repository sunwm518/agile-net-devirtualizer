namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Executable edges for SSA. Linear VM layout can place a handler immediately after its try and
/// therefore expose a syntactic fallthrough into the handler. CLR control flow enters a handler only
/// through an exceptional edge; the semantic emitter inserts the required leave at that boundary.
/// </summary>
internal static class SsaControlFlow
{
    public static IEnumerable<ControlFlowEdge> Incoming(
        SemanticControlFlowGraph graph,
        BasicBlock block) => graph.Incoming(block).Where(edge => IsExecutable(graph, edge));

    public static IEnumerable<ControlFlowEdge> Outgoing(
        SemanticControlFlowGraph graph,
        BasicBlock block) => graph.Outgoing(block).Where(edge => IsExecutable(graph, edge));

    public static bool IsExecutable(
        SemanticControlFlowGraph graph,
        ControlFlowEdge edge)
    {
        if (ControlFlowEdgeSemantics.IsException(edge.Kind))
            return true;

        var source = graph.Blocks[edge.SourceBlockId].RegionPath;
        var target = graph.Blocks[edge.TargetBlockId].RegionPath;
        return !target.Frames.Any(frame => frame.Zone is RegionZone.Filter or RegionZone.Handler
            && !source.Frames.Contains(frame));
    }
}
