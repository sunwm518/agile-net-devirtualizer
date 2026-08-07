namespace AgileDevirtualizer.Analysis;

internal sealed record ConstantBranchElimination(
    FoldedTerminatorPlan Terminator,
    IReadOnlyDictionary<int, IReadOnlySet<int>> RemovableInstructionsByBlock);

internal sealed class ConstantBranchEliminationResult
{
    public ConstantBranchEliminationResult(
        ControlFlowSimplificationResult simplification,
        IReadOnlyList<ConstantBranchElimination> eliminations,
        IReadOnlyList<string> rejections)
    {
        Simplification = simplification;
        Eliminations = eliminations;
        Rejections = rejections;
    }

    public ControlFlowSimplificationResult Simplification { get; }
    public IReadOnlyList<ConstantBranchElimination> Eliminations { get; }
    public IReadOnlyList<string> Rejections { get; }
}

internal static class ConstantBranchEliminationPlanner
{
    public static ConstantBranchEliminationResult Analyze(
        ControlFlowSimplificationResult simplification)
    {
        var eliminations = new List<ConstantBranchElimination>();
        var rejections = new List<string>();
        foreach (var folded in simplification.FoldedTerminators)
        {
            if (TryPlan(folded, simplification, out var elimination, out string reason))
                eliminations.Add(elimination);
            else
                rejections.Add($"B{folded.BlockId}: {reason}");
        }
        return new ConstantBranchEliminationResult(simplification, eliminations, rejections);
    }

    private static bool TryPlan(
        FoldedTerminatorPlan folded,
        ControlFlowSimplificationResult simplification,
        out ConstantBranchElimination elimination,
        out string reason)
    {
        elimination = null!;
        reason = string.Empty;
        var sccp = simplification.DeadCode.Sccp;
        var graph = sccp.Graph;
        var block = graph.Blocks[folded.BlockId];
        if (block.Terminator is not { } terminator || terminator.Inputs.Count == 0)
        {
            reason = "folded terminator has no SSA selector inputs";
            return false;
        }
        if (!ControlFlowSimplifier.SameRegion(
            graph.Source.Blocks[block.Id].RegionPath,
            graph.Source.Blocks[folded.SelectedEdge.TargetBlockId].RegionPath))
        {
            reason = "selected branch crosses an exception-region boundary";
            return false;
        }

        var byOutput = graph.Blocks.Where(candidate =>
                candidate.Reachable && sccp.ExecutableBlocks.Contains(candidate.Id))
            .SelectMany(candidate => candidate.Instructions)
            .SelectMany(instruction => instruction.Outputs.Select(output => (output, instruction)))
            .ToDictionary(pair => pair.output, pair => pair.instruction);
        var phis = graph.Blocks.SelectMany(candidate => candidate.Phis)
            .ToDictionary(phi => phi.Result.Id);
        var removable = new Dictionary<int, HashSet<int>>();
        var traversedPhis = new HashSet<int>();
        var values = new Stack<int>(terminator.Inputs);
        while (values.Count > 0)
        {
            int valueId = values.Pop();
            if (phis.TryGetValue(valueId, out var phi))
            {
                if (sccp.Values[valueId].Kind != SccpValueKind.Constant)
                {
                    reason = $"phi %{valueId} is not constant";
                    return false;
                }
                if (!traversedPhis.Add(valueId))
                    continue;
                foreach (var input in phi.Inputs.Where(input => IsExecutableInput(
                    input, phi.Result.DefinitionBlockId!.Value, sccp)))
                    values.Push(input.ValueId);
                continue;
            }
            if (!byOutput.TryGetValue(valueId, out var definition)
                || !SemanticEffectClassifier.CanReplaceWithConstant(definition)
                || sccp.Values[valueId].Kind != SccpValueKind.Constant)
            {
                reason = $"%{valueId} is not a local pure constant definition";
                return false;
            }
            if (!removable.TryGetValue(definition.BlockId, out var blockRemovals))
                removable[definition.BlockId] = blockRemovals = [];
            if (!blockRemovals.Add(definition.Id))
                continue;
            foreach (int input in definition.Inputs)
                values.Push(input);
            AddPrefixes(definition, graph.Blocks[definition.BlockId], blockRemovals);
        }

        foreach (var pair in removable)
        {
            var removalBlock = graph.Blocks[pair.Key];
            int first = pair.Value.Select(id => removalBlock.Instructions
                .Single(instruction => instruction.Id == id).Ordinal).Min();
            if (!removalBlock.Instructions.Skip(first).Select(instruction => instruction.Id)
                .ToHashSet().SetEquals(pair.Value))
            {
                reason = $"B{pair.Key} constant slice is not an instruction suffix";
                return false;
            }
            if (!ControlFlowSimplifier.SameRegion(
                graph.Source.Blocks[pair.Key].RegionPath,
                graph.Source.Blocks[block.Id].RegionPath))
            {
                reason = $"B{pair.Key} constant slice crosses an exception-region boundary";
                return false;
            }
        }
        if (!OutputsArePrivate(removable, traversedPhis, block, graph))
        {
            reason = "constant-condition calculation has another use";
            return false;
        }

        elimination = new ConstantBranchElimination(folded,
            removable.ToDictionary(pair => pair.Key,
                pair => (IReadOnlySet<int>)pair.Value));
        return true;
    }

    private static bool OutputsArePrivate(
        IReadOnlyDictionary<int, HashSet<int>> removable,
        IReadOnlySet<int> traversedPhis,
        SsaBlock block,
        SsaGraph graph)
    {
        var outputs = removable.SelectMany(pair => graph.Blocks[pair.Key].Instructions
                .Where(instruction => pair.Value.Contains(instruction.Id)))
            .SelectMany(instruction => instruction.Outputs).ToHashSet();
        foreach (var use in graph.Uses.Where(use => outputs.Contains(use.ValueId)))
        {
            if (use.Kind == SsaUseKind.InstructionInput)
            {
                var consumer = graph.Blocks[use.BlockId].Instructions
                    .Single(instruction => instruction.Ordinal == use.InstructionOrdinal);
                if (!removable.TryGetValue(use.BlockId, out var ids)
                    || !ids.Contains(consumer.Id))
                    return false;
                continue;
            }
            if (use.Kind == SsaUseKind.TerminatorInput && use.BlockId == block.Id)
                continue;
            if (use.Kind == SsaUseKind.PhiInput
                && graph.Blocks[use.BlockId].Phis.Any(phi =>
                    traversedPhis.Contains(phi.Result.Id)
                    && phi.Inputs.Any(input => input.ValueId == use.ValueId)))
                continue;
            return false;
        }
        return true;
    }

    private static void AddPrefixes(
        SsaInstruction instruction,
        SsaBlock block,
        ISet<int> removable)
    {
        for (int ordinal = instruction.Ordinal - 1; ordinal >= 0; ordinal--)
        {
            var prefix = block.Instructions[ordinal];
            if (prefix.Operation.Code != SemanticOperationCode.Prefix)
                break;
            removable.Add(prefix.Id);
        }
    }

    private static bool IsExecutableInput(
        SsaPhiInput input,
        int targetBlockId,
        SccpResult sccp) => input.Kind == SsaPhiInputKind.MethodEntry
        || sccp.ExecutableEdges.Any(edge => edge.SourceBlockId == input.PredecessorBlockId
            && edge.TargetBlockId == targetBlockId);
}
