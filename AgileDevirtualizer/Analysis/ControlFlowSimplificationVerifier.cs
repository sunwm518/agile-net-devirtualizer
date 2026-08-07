namespace AgileDevirtualizer.Analysis;

internal sealed record ControlFlowSimplificationVerificationResult(
    IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class ControlFlowSimplificationVerifier
{
    public static ControlFlowSimplificationVerificationResult Verify(
        ControlFlowSimplificationResult result)
    {
        var errors = new List<string>();
        var sccp = result.DeadCode.Sccp;
        var graph = sccp.Graph;

        if (!result.RetainedBlockIds.SetEquals(sccp.ExecutableBlocks))
            errors.Add("retained blocks differ from the SCCP executable set");
        if (!result.RetainedEdges.SetEquals(sccp.ExecutableEdges))
            errors.Add("retained edges differ from the SCCP executable set");

        var foldedByBlock = result.FoldedTerminators.ToDictionary(plan => plan.BlockId);
        foreach (var block in graph.Blocks.Where(block =>
            block.Reachable && result.RetainedBlockIds.Contains(block.Id)))
        {
            if (block.Terminator is not { } terminator)
                continue;
            var normal = ControlFlowSimplifier.NormalOutgoing(graph.Source, block.Id).ToArray();
            var decision = SccpEvaluator.Decide(terminator, sccp.Values);
            bool mustFold = normal.Length > 1 && decision.Known;
            if (mustFold != foldedByBlock.ContainsKey(block.Id))
            {
                errors.Add($"B{block.Id} folded-terminator plan mismatch");
                continue;
            }
            if (!mustFold)
                continue;
            var plan = foldedByBlock[block.Id];
            var selected = normal.Where(result.RetainedEdges.Contains).ToArray();
            if (selected.Length != 1 || selected[0] != plan.SelectedEdge)
                errors.Add($"B{block.Id} does not have one SCCP-selected normal edge");
            if (plan.Decision != decision
                || plan.OriginalKind != terminator.Terminator.Kind)
                errors.Add($"B{block.Id} folded decision lost semantic provenance");
        }

        foreach (var dispatcher in result.Dispatchers)
        {
            var block = graph.Blocks[dispatcher.BlockId];
            if (!ControlFlowSimplifier.TryBuildDispatcher(block, graph, sccp,
                result.RetainedEdges, out var rebuilt)
                || rebuilt.SelectorValueId != dispatcher.SelectorValueId
                || !rebuilt.StateTargets.OrderBy(pair => pair.Key)
                    .SequenceEqual(dispatcher.StateTargets.OrderBy(pair => pair.Key))
                || !rebuilt.Transitions.OrderBy(item => item.PredecessorBlockId)
                    .SequenceEqual(dispatcher.Transitions.OrderBy(item => item.PredecessorBlockId)))
                errors.Add($"B{dispatcher.BlockId} is not a finite cyclic state dispatcher");
            if (dispatcher.StateTargets.Count < 2
                || dispatcher.StateTargets.Values.Any(edge =>
                    !result.RetainedEdges.Contains(edge)))
                errors.Add($"B{dispatcher.BlockId} has an invalid state-to-edge map");
        }

        var redirects = result.TrivialRedirects.ToDictionary(plan => plan.BlockId);
        foreach (var redirect in redirects.Values)
        {
            var block = graph.Blocks[redirect.BlockId];
            if (!ControlFlowSimplifier.IsTrivialRedirect(block, graph, result.DeadCode,
                result.RetainedBlockIds, result.RetainedEdges))
                errors.Add($"B{redirect.BlockId} is not a safe trivial redirect");
            var outgoing = ControlFlowSimplifier.NormalOutgoing(graph.Source, block.Id)
                .Where(result.RetainedEdges.Contains).ToArray();
            if (outgoing.Length != 1 || outgoing[0].TargetBlockId != redirect.TargetBlockId)
                errors.Add($"B{redirect.BlockId} redirect target is inconsistent");
        }

        return new ControlFlowSimplificationVerificationResult(errors);
    }
}
