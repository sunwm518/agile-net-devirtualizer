namespace AgileDevirtualizer.Analysis;

internal sealed record DeadCodeStatistics(
    int ExecutableInstructions,
    int LiveInstructions,
    int RemovedInstructions,
    int LiveValues,
    int ConstantReplacements,
    int SideEffectRoots);

internal sealed class DeadCodeResult
{
    public DeadCodeResult(
        SccpResult sccp,
        IReadOnlySet<int> liveInstructionIds,
        IReadOnlySet<int> liveValueIds,
        IReadOnlyDictionary<int, object?> constantReplacements,
        IReadOnlySet<int> sideEffectRootIds)
    {
        Sccp = sccp;
        LiveInstructionIds = liveInstructionIds;
        LiveValueIds = liveValueIds;
        ConstantReplacements = constantReplacements;
        SideEffectRootIds = sideEffectRootIds;
    }

    public SccpResult Sccp { get; }
    public IReadOnlySet<int> LiveInstructionIds { get; }
    public IReadOnlySet<int> LiveValueIds { get; }
    public IReadOnlyDictionary<int, object?> ConstantReplacements { get; }
    public IReadOnlySet<int> SideEffectRootIds { get; }
}

internal static class SsaDeadCodeAnalysis
{
    public static DeadCodeResult Analyze(SccpResult sccp)
    {
        var graph = sccp.Graph;
        var executableBlocks = graph.Blocks.Where(block =>
            block.Reachable && sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        var instructions = executableBlocks.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var outputDefinitions = instructions.Values
            .SelectMany(instruction => instruction.Outputs.Select(output => (output, instruction)))
            .ToDictionary(pair => pair.output, pair => pair.instruction);
        var phis = executableBlocks.SelectMany(block => block.Phis)
            .ToDictionary(phi => phi.Result.Id);
        var liveInstructions = new HashSet<int>();
        var liveValues = new HashSet<int>();
        var replacements = new Dictionary<int, object?>();
        var sideEffectRoots = new HashSet<int>();
        var valueQueue = new Queue<int>();
        var instructionQueue = new Queue<int>();

        foreach (var block in executableBlocks)
        {
            if (block.Terminator is { } terminator)
                foreach (int input in terminator.Inputs)
                    valueQueue.Enqueue(input);
            foreach (var instruction in block.Instructions)
            {
                if (SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation))
                    continue;
                sideEffectRoots.Add(instruction.Id);
                instructionQueue.Enqueue(instruction.Id);
            }
        }

        while (instructionQueue.Count > 0 || valueQueue.Count > 0)
        {
            while (instructionQueue.Count > 0)
            {
                int instructionId = instructionQueue.Dequeue();
                if (!liveInstructions.Add(instructionId))
                    continue;
                var instruction = instructions[instructionId];
                foreach (int input in instruction.Inputs)
                    valueQueue.Enqueue(input);
                MarkPrefixes(instruction, graph.Blocks[instruction.BlockId],
                    liveInstructions, instructionQueue);
            }

            if (valueQueue.Count == 0)
                continue;
            int valueId = valueQueue.Dequeue();
            if (!liveValues.Add(valueId))
                continue;
            if (sccp.Values[valueId] is { Kind: SccpValueKind.Constant } constant)
            {
                if (phis.ContainsKey(valueId)
                    || outputDefinitions.TryGetValue(valueId, out var constantDefinition)
                    && SemanticEffectClassifier.CanReplaceWithConstant(constantDefinition))
                {
                    replacements[valueId] = constant.Constant;
                    continue;
                }
            }
            if (phis.TryGetValue(valueId, out var phi))
            {
                foreach (var input in phi.Inputs.Where(input => IsExecutableInput(
                    input, phi.Result.DefinitionBlockId!.Value, sccp)))
                    valueQueue.Enqueue(input.ValueId);
                continue;
            }
            if (outputDefinitions.TryGetValue(valueId, out var definition))
                instructionQueue.Enqueue(definition.Id);
        }

        return new DeadCodeResult(sccp, liveInstructions, liveValues,
            replacements, sideEffectRoots);
    }

    public static DeadCodeStatistics Statistics(DeadCodeResult result)
    {
        int executable = result.Sccp.Graph.Blocks.Where(block =>
                block.Reachable && result.Sccp.ExecutableBlocks.Contains(block.Id))
            .Sum(block => block.Instructions.Count);
        return new DeadCodeStatistics(executable, result.LiveInstructionIds.Count,
            executable - result.LiveInstructionIds.Count, result.LiveValueIds.Count,
            result.ConstantReplacements.Count, result.SideEffectRootIds.Count);
    }

    private static bool IsExecutableInput(
        SsaPhiInput input,
        int targetBlockId,
        SccpResult sccp) => input.Kind == SsaPhiInputKind.MethodEntry
        || sccp.ExecutableEdges.Any(edge => edge.SourceBlockId == input.PredecessorBlockId
            && edge.TargetBlockId == targetBlockId);

    private static void MarkPrefixes(
        SsaInstruction instruction,
        SsaBlock block,
        ISet<int> live,
        Queue<int> queue)
    {
        for (int ordinal = instruction.Ordinal - 1; ordinal >= 0; ordinal--)
        {
            var candidate = block.Instructions[ordinal];
            if (candidate.Operation.Code != SemanticOperationCode.Prefix)
                break;
            if (!live.Contains(candidate.Id))
                queue.Enqueue(candidate.Id);
        }
    }
}
