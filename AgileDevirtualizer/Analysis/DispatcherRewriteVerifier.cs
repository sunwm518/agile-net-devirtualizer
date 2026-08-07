namespace AgileDevirtualizer.Analysis;

internal sealed record DispatcherRewriteVerificationResult(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class DispatcherRewriteVerifier
{
    public static DispatcherRewriteVerificationResult Verify(DispatcherRewriteResult result)
    {
        var errors = ControlFlowGraphValidator.Validate(result.Graph).ToList();
        var sourceSsa = result.Plan.Simplification.DeadCode.Sccp.Graph;
        foreach (var elimination in result.Plan.Eliminations)
        {
            foreach (var transition in elimination.Dispatcher.Transitions)
            {
                var block = result.Graph.Blocks[transition.PredecessorBlockId];
                int targetInstruction = result.Graph.Blocks[
                    transition.SelectedEdge.TargetBlockId].StartInstructionIndex;
                if (block.Terminator.Kind != SemanticTerminatorKind.Branch
                    || !block.Terminator.TargetInstructionIndices.SequenceEqual([targetInstruction]))
                    errors.Add($"B{block.Id} was not redirected to its selected state target");
                if (!result.Graph.Outgoing(block).Any(edge =>
                    edge.TargetBlockId == transition.SelectedEdge.TargetBlockId
                    && edge.Kind == ControlFlowEdgeKind.Branch))
                    errors.Add($"B{block.Id} is missing its rewritten CFG edge");

                var slice = elimination.StateSlices.Single(item =>
                    item.PredecessorBlockId == transition.PredecessorBlockId);
                var remaining = result.Graph.Blocks[block.Id].Operations;
                var expected = sourceSsa.Blocks[block.Id].Instructions
                    .Where(instruction => !slice.RemovableInstructionIds.Contains(instruction.Id))
                    .Select(instruction => instruction.Operation).ToArray();
                if (!remaining.SequenceEqual(expected))
                    errors.Add($"B{block.Id} state-slice rewrite changed unrelated operations");
            }
        }

        var worklist = WorklistAnalyzer.Analyze(result.Graph);
        if (!worklist.Converged)
            errors.Add("rewritten CFG worklist did not converge");
        foreach (string diagnostic in worklist.Diagnostics.Where(message =>
            !message.Contains("unreachable", StringComparison.OrdinalIgnoreCase)))
            errors.Add("rewritten CFG: " + diagnostic);
        return new DispatcherRewriteVerificationResult(errors);
    }
}
