namespace AgileDevirtualizer.Analysis;

internal sealed record OptimizedGraphVerificationResult(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class OptimizedGraphVerifier
{
    public static OptimizedGraphVerificationResult Verify(OptimizedGraphRewriteResult result)
    {
        var errors = ControlFlowGraphValidator.Validate(result.Graph).ToList();
        var ssa = result.Dispatchers.Simplification.DeadCode.Sccp.Graph;
        var removals = new Dictionary<int, HashSet<int>>();
        var targets = new Dictionary<int, int>();
        foreach (var elimination in result.Dispatchers.Eliminations)
        {
            foreach (var transition in elimination.Dispatcher.Transitions)
                targets[transition.PredecessorBlockId] = transition.SelectedEdge.TargetBlockId;
            foreach (var slice in elimination.StateSlices)
                Add(slice.PredecessorBlockId, slice.RemovableInstructionIds);
        }
        foreach (var elimination in result.Branches.Eliminations)
        {
            targets[elimination.Terminator.BlockId] =
                elimination.Terminator.SelectedEdge.TargetBlockId;
            foreach (var pair in elimination.RemovableInstructionsByBlock)
                Add(pair.Key, pair.Value);
        }

        foreach (var pair in targets)
        {
            int blockId = pair.Key;
            int targetId = pair.Value;
            var block = result.Graph.Blocks[blockId];
            int targetInstruction = result.Graph.Blocks[targetId].StartInstructionIndex;
            if (block.Terminator.Kind != SemanticTerminatorKind.Branch
                || !block.Terminator.TargetInstructionIndices.SequenceEqual([targetInstruction]))
                errors.Add($"B{blockId} does not branch directly to B{targetId}");
            var normal = SsaControlFlow.Outgoing(result.Graph, block)
                .Where(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)).ToArray();
            if (normal.Length != 1 || normal[0].TargetBlockId != targetId
                || normal[0].Kind != ControlFlowEdgeKind.Branch)
                errors.Add($"B{blockId} rewritten edge does not match its terminator");
            var ids = removals.GetValueOrDefault(blockId) ?? [];
            var expected = ssa.Blocks[blockId].Instructions
                .Where(instruction => !ids.Contains(instruction.Id))
                .Select(instruction => instruction.Operation).ToArray();
            if (!block.Operations.SequenceEqual(expected))
                errors.Add($"B{blockId} rewrite changed an unrelated semantic operation");
        }
        foreach (var pair in removals.Where(pair => !targets.ContainsKey(pair.Key)))
        {
            var expected = ssa.Blocks[pair.Key].Instructions
                .Where(instruction => !pair.Value.Contains(instruction.Id))
                .Select(instruction => instruction.Operation).ToArray();
            if (!result.Graph.Blocks[pair.Key].Operations.SequenceEqual(expected))
                errors.Add($"B{pair.Key} cross-block constant slice was not removed exactly");
        }

        var worklist = WorklistAnalyzer.Analyze(result.Graph);
        if (!worklist.Converged)
            errors.Add("optimized CFG worklist did not converge");
        foreach (string diagnostic in worklist.Diagnostics.Where(message =>
            !message.Contains("unreachable", StringComparison.OrdinalIgnoreCase)))
            errors.Add("optimized CFG: " + diagnostic);
        return new OptimizedGraphVerificationResult(errors);

        void Add(int blockId, IEnumerable<int> ids)
        {
            if (!removals.TryGetValue(blockId, out var destination))
                removals[blockId] = destination = [];
            destination.UnionWith(ids);
        }
    }
}
