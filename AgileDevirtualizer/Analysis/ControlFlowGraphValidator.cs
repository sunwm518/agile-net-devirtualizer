namespace AgileDevirtualizer.Analysis;

/// <summary>Pure invariant checks for the observational graph; never affects devirtualization.</summary>
internal static class ControlFlowGraphValidator
{
    public static IReadOnlyList<string> Validate(SemanticControlFlowGraph graph)
    {
        var errors = new List<string>();
        int expectedStart = 0;
        for (int id = 0; id < graph.Blocks.Count; id++)
        {
            var block = graph.Blocks[id];
            if (block.Id != id)
                errors.Add($"block position {id} has id B{block.Id}");
            if (block.StartInstructionIndex != expectedStart)
                errors.Add($"B{block.Id} starts at {block.StartInstructionIndex}, expected {expectedStart}");
            if (block.EndInstructionIndex < block.StartInstructionIndex)
                errors.Add($"B{block.Id} has an empty/reversed range");
            expectedStart = block.EndInstructionIndex + 1;
        }
        if (expectedStart != graph.InstructionCount)
            errors.Add($"blocks cover {expectedStart} VM instructions, expected {graph.InstructionCount}");

        foreach (var edge in graph.Edges)
        {
            if (edge.SourceBlockId < 0 || edge.SourceBlockId >= graph.Blocks.Count)
                errors.Add($"edge has invalid source B{edge.SourceBlockId}");
            if (edge.TargetBlockId < 0 || edge.TargetBlockId >= graph.Blocks.Count)
                errors.Add($"edge has invalid target B{edge.TargetBlockId}");
            if (ControlFlowEdgeSemantics.IsException(edge.Kind) && edge.ExceptionRegionId is null)
                errors.Add($"{edge.Kind} edge B{edge.SourceBlockId}->B{edge.TargetBlockId} lacks EH id");
            if (!ControlFlowEdgeSemantics.IsException(edge.Kind) && edge.ExceptionRegionId is not null)
                errors.Add($"normal edge B{edge.SourceBlockId}->B{edge.TargetBlockId} has EH id");
        }

        foreach (var block in graph.Blocks)
        {
            var normal = graph.Outgoing(block)
                .Where(edge => !ControlFlowEdgeSemantics.IsException(edge.Kind)).ToArray();
            int expectedMinimum = block.Terminator.Kind switch
            {
                SemanticTerminatorKind.FallThrough when
                    block.EndInstructionIndex + 1 < graph.InstructionCount => 1,
                SemanticTerminatorKind.Branch => 1,
                SemanticTerminatorKind.Conditional => 2,
                SemanticTerminatorKind.Switch => block.Terminator.TargetInstructionIndices.Count + 1,
                _ => 0,
            };
            if (normal.Length < expectedMinimum)
                errors.Add($"B{block.Id} {block.Terminator.Kind} has {normal.Length} normal edges, "
                    + $"expected at least {expectedMinimum}");
        }
        return errors;
    }
}
