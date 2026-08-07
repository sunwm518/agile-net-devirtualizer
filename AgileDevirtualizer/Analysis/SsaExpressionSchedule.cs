namespace AgileDevirtualizer.Analysis;

internal sealed record SsaExpressionRoot(int InstructionId, bool DiscardResult);

internal sealed record SsaExpressionSchedule(
    DeadCodeResult DeadCode,
    bool Eligible,
    string Reason,
    SsaBlock? Block,
    IReadOnlyList<SsaExpressionRoot> Roots,
    IReadOnlyList<int> PlannedInstructionIds)
{
    public static SsaExpressionSchedule Reject(DeadCodeResult deadCode, string reason) =>
        new(deadCode, false, reason, null, [], []);
}

/// <summary>
/// Proves that a single-block SSA graph can be emitted as expression trees without spills. Besides
/// the structural gate, the planner requires the exact original order of every potentially
/// throwing or externally visible operation. Pure calculations may move only inside those trees.
/// </summary>
internal static class SsaExpressionScheduler
{
    public static SsaExpressionSchedule Plan(DeadCodeResult deadCode)
    {
        var requirements = SsaLoweringRequirementAnalyzer.Analyze(deadCode.Sccp);
        if (!requirements.ExactStraightLineCandidate)
            return SsaExpressionSchedule.Reject(deadCode,
                $"requires {requirements.Features}");

        var graph = deadCode.Sccp.Graph;
        var blocks = graph.Blocks.Where(block => block.Reachable
            && deadCode.Sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        if (blocks.Length != 1 || blocks[0].Phis.Count != 0)
            return SsaExpressionSchedule.Reject(deadCode,
                "expression lowering requires one executable block without phi nodes");

        var block = blocks[0];
        var instructions = block.Instructions.ToDictionary(instruction => instruction.Id);
        var definitions = block.Instructions
            .SelectMany(instruction => instruction.Outputs.Select(valueId =>
                (ValueId: valueId, Instruction: instruction)))
            .ToDictionary(pair => pair.ValueId, pair => pair.Instruction);
        var instructionByLocation = block.Instructions.ToDictionary(
            instruction => (instruction.BlockId, instruction.Ordinal));
        var roots = new List<SsaExpressionRoot>();

        foreach (var instruction in block.Instructions.Where(instruction =>
            deadCode.LiveInstructionIds.Contains(instruction.Id)
            && !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation)))
        {
            if (instruction.Outputs.Count > 1)
                return SsaExpressionSchedule.Reject(deadCode,
                    $"I{instruction.Id} has multiple outputs");
            bool consumed = instruction.Outputs.Any(valueId => HasLiveConsumer(valueId));
            if (instruction.Outputs.Count == 0 || !consumed)
                roots.Add(new SsaExpressionRoot(instruction.Id,
                    instruction.Outputs.Count == 1));
        }

        var planned = new List<int>();
        var emitted = new HashSet<int>();
        foreach (var root in roots)
        {
            var instruction = instructions[root.InstructionId];
            foreach (int input in instruction.Inputs)
                if (!AppendValue(input, out string? error))
                    return SsaExpressionSchedule.Reject(deadCode, error!);
            if (!AppendInstruction(instruction, out string? rootError))
                return SsaExpressionSchedule.Reject(deadCode, rootError!);
        }

        if (block.Terminator is not { } terminator)
            return SsaExpressionSchedule.Reject(deadCode, "block has no SSA terminator");
        foreach (int input in terminator.Inputs)
            if (!AppendValue(input, out string? error))
                return SsaExpressionSchedule.Reject(deadCode, error!);

        var expectedEffects = block.Instructions.Where(instruction =>
                deadCode.LiveInstructionIds.Contains(instruction.Id)
                && !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation))
            .Select(instruction => instruction.Id).ToArray();
        var plannedEffects = planned.Where(id =>
                !SemanticEffectClassifier.IsRemovableIfUnused(instructions[id].Operation))
            .ToArray();
        if (!expectedEffects.SequenceEqual(plannedEffects))
            return SsaExpressionSchedule.Reject(deadCode,
                "expression scheduling would reorder observable or throwing operations");

        return new SsaExpressionSchedule(deadCode, true, "eligible", block,
            roots, planned.ToArray());

        bool HasLiveConsumer(int valueId) => graph.Uses.Any(use =>
            use.ValueId == valueId && (use.Kind == SsaUseKind.TerminatorInput
                || use.Kind == SsaUseKind.InstructionInput
                && instructionByLocation.TryGetValue((use.BlockId,
                    use.InstructionOrdinal!.Value), out var consumer)
                && deadCode.LiveInstructionIds.Contains(consumer.Id)));

        bool AppendValue(int valueId, out string? error)
        {
            error = null;
            if (deadCode.ConstantReplacements.ContainsKey(valueId))
                return true;
            var value = graph.Value(valueId);
            if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal)
                return true;
            if (value.Kind != SsaValueKind.Operation
                || !definitions.TryGetValue(valueId, out var definition))
            {
                error = $"value %{valueId} has no spill-free materialization";
                return false;
            }
            if (!deadCode.LiveInstructionIds.Contains(definition.Id))
            {
                error = $"definition I{definition.Id} of %{valueId} is not live";
                return false;
            }
            foreach (int input in definition.Inputs)
                if (!AppendValue(input, out error))
                    return false;
            return AppendInstruction(definition, out error);
        }

        bool AppendInstruction(SsaInstruction instruction, out string? error)
        {
            error = null;
            if (!emitted.Add(instruction.Id))
            {
                error = $"I{instruction.Id} would be emitted more than once";
                return false;
            }
            planned.Add(instruction.Id);
            return true;
        }
    }
}
