namespace AgileDevirtualizer.Analysis;

internal sealed record SccpVerificationResult(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class SccpVerifier
{
    public static SccpVerificationResult Verify(SccpResult result)
    {
        var errors = new List<string>();
        var graph = result.Graph;
        if (!result.Converged)
            errors.Add("SCCP did not converge");
        if (graph.Blocks.Count > 0 && graph.Blocks[0].Reachable
            && !result.ExecutableBlocks.Contains(0))
            errors.Add("method entry is not executable");
        if (result.Values.Count != graph.Values.Count
            || graph.Values.Any(value => !result.Values.ContainsKey(value.Id)))
            errors.Add("SCCP lattice does not classify every SSA value");

        var executableUniverse = graph.Source.Edges
            .Where(edge => SsaControlFlow.IsExecutable(graph.Source, edge)).ToHashSet();
        foreach (var edge in result.ExecutableEdges)
        {
            if (!executableUniverse.Contains(edge))
                errors.Add($"SCCP selected a non-semantic edge B{edge.SourceBlockId}->B{edge.TargetBlockId}");
            if (!result.ExecutableBlocks.Contains(edge.SourceBlockId)
                || !result.ExecutableBlocks.Contains(edge.TargetBlockId))
                errors.Add($"executable edge B{edge.SourceBlockId}->B{edge.TargetBlockId} "
                    + "has an infeasible endpoint");
        }
        foreach (int blockId in result.ExecutableBlocks)
        {
            if (blockId < 0 || blockId >= graph.Blocks.Count || !graph.Blocks[blockId].Reachable)
                errors.Add($"SCCP selected invalid/unreachable B{blockId}");
        }

        foreach (var block in graph.Blocks.Where(block =>
            block.Reachable && result.ExecutableBlocks.Contains(block.Id)))
        {
            VerifyPhiFixedPoint(block, result, errors);
            VerifyOperationFixedPoint(block, result, errors);
            VerifyTerminator(block, result, errors);
        }
        foreach (var value in graph.Values)
        {
            var lattice = result.Values[value.Id];
            if (lattice.Kind == SccpValueKind.Constant
                && !ConstantCompatible(value.AbstractValue, lattice.Constant))
                errors.Add($"%{value.Id} constant {lattice.Constant ?? "null"} is incompatible "
                    + $"with {value.AbstractValue}");
        }
        return new SccpVerificationResult(errors);
    }

    private static void VerifyPhiFixedPoint(
        SsaBlock block,
        SccpResult result,
        List<string> errors)
    {
        foreach (var phi in block.Phis)
        {
            var expected = SccpValue.Undefined;
            foreach (var input in phi.Inputs.Where(input =>
                input.Kind == SsaPhiInputKind.MethodEntry
                || result.ExecutableEdges.Any(edge =>
                    edge.SourceBlockId == input.PredecessorBlockId
                    && edge.TargetBlockId == block.Id)))
                expected = SccpValue.Join(expected, result.Values[input.ValueId]);
            if (result.Values[phi.Result.Id] != expected)
                errors.Add($"B{block.Id} phi %{phi.Result.Id} is not at its SCCP fixed point");
        }
    }

    private static void VerifyOperationFixedPoint(
        SsaBlock block,
        SccpResult result,
        List<string> errors)
    {
        foreach (var instruction in block.Instructions.Where(instruction =>
            instruction.Outputs.Count > 0))
        {
            var inputs = instruction.Inputs.Select(id => result.Values[id]).ToArray();
            foreach (int output in instruction.Outputs)
            {
                var expected = SccpEvaluator.Evaluate(instruction, inputs,
                    result.Graph.Value(output).AbstractValue, out _);
                if (result.Values[output] != expected)
                    errors.Add($"B{block.Id} instruction {instruction.Ordinal} output %{output} "
                        + "is not at its SCCP fixed point");
            }
        }
    }

    private static void VerifyTerminator(
        SsaBlock block,
        SccpResult result,
        List<string> errors)
    {
        if (block.Terminator is not { } terminator)
            return;
        var normal = SsaControlFlow.Outgoing(result.Graph.Source,
                result.Graph.Source.Blocks[block.Id])
            .Where(edge => !IsExceptionEdge(edge.Kind)).ToArray();
        if (normal.Length == 0)
            return;
        var decision = SccpEvaluator.Decide(terminator, result.Values);
        int selected = normal.Count(result.ExecutableEdges.Contains);
        if (!decision.Known && selected != normal.Length)
            errors.Add($"B{block.Id} unknown terminator did not retain every normal edge");
        if (decision.Known && selected != 1)
            errors.Add($"B{block.Id} folded terminator selected {selected} normal edges");
    }

    private static bool ConstantCompatible(AbstractValue type, object? constant) => type.Kind switch
    {
        AbstractValueKind.Unknown => true,
        AbstractValueKind.Int32 => constant is bool or byte or sbyte or short or ushort
            or int or uint or char,
        AbstractValueKind.Int64 => constant is long or ulong,
        AbstractValueKind.NativeInt => constant is int or uint or long or ulong,
        AbstractValueKind.Float32 => constant is float,
        AbstractValueKind.Float64 => constant is double,
        AbstractValueKind.Reference => constant is null or string,
        _ => constant is not null,
    };

    private static bool IsExceptionEdge(ControlFlowEdgeKind kind) =>
        ControlFlowEdgeSemantics.IsException(kind);
}
