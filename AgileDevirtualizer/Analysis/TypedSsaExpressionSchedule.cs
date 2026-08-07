using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record TypedSsaExpressionRoot(
    int InstructionId,
    int? SpillOutputValueId,
    bool DiscardResult);

internal sealed record TypedSsaExpressionSchedule(
    DeadCodeResult DeadCode,
    SsaCilTypeResult Types,
    bool Eligible,
    string Reason,
    SsaBlock? Block,
    IReadOnlyList<TypedSsaExpressionRoot> Roots,
    IReadOnlyDictionary<int, TypeSignature> SpillTypes,
    IReadOnlyList<int> PlannedInstructionIds)
{
    public static TypedSsaExpressionSchedule Reject(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        string reason) => new(deadCode, types, false, reason, null, [],
            new Dictionary<int, TypeSignature>(), []);
}

/// <summary>
/// Extends spill-free expression scheduling with typed locals. Values are spilled only when they
/// have multiple live uses or when retaining them as nested expressions would reorder an observable
/// or potentially throwing operation.
/// </summary>
internal static class TypedSsaExpressionScheduler
{
    public static TypedSsaExpressionSchedule Plan(
        DeadCodeResult deadCode,
        SsaCilTypeResult types)
    {
        if (!ReferenceEquals(deadCode.Sccp.Graph, types.Graph) || !types.Converged)
            return TypedSsaExpressionSchedule.Reject(deadCode, types,
                "CIL types do not belong to this SSA graph or did not converge");
        var requirements = SsaLoweringRequirementAnalyzer.Analyze(deadCode.Sccp);
        if (!requirements.StraightLineCandidate)
            return TypedSsaExpressionSchedule.Reject(deadCode, types,
                $"requires {requirements.Features}");

        var graph = deadCode.Sccp.Graph;
        var blocks = graph.Blocks.Where(block => block.Reachable
            && deadCode.Sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        if (blocks.Length != 1 || blocks[0].Phis.Count != 0)
            return TypedSsaExpressionSchedule.Reject(deadCode, types,
                "typed expression lowering requires one executable block without phi nodes");
        var block = blocks[0];
        var instructions = block.Instructions.ToDictionary(instruction => instruction.Id);
        var definitions = block.Instructions
            .SelectMany(instruction => instruction.Outputs.Select(valueId =>
                (ValueId: valueId, Instruction: instruction)))
            .ToDictionary(pair => pair.ValueId, pair => pair.Instruction);
        var instructionByLocation = block.Instructions.ToDictionary(
            instruction => (instruction.BlockId, instruction.Ordinal));
        var spills = new HashSet<int>();

        foreach (var instruction in block.Instructions.Where(IsLive))
        {
            if (instruction.Outputs.Count > 1)
                return TypedSsaExpressionSchedule.Reject(deadCode, types,
                    $"I{instruction.Id} has multiple outputs");
            if (instruction.Outputs.Count == 1
                && !deadCode.ConstantReplacements.ContainsKey(instruction.Outputs[0])
                && LiveConsumerCount(instruction.Outputs[0]) > 1)
                spills.Add(instruction.Outputs[0]);
        }

        for (int attempt = 0; attempt < 2; attempt++)
        {
            if (!TrySpillTypes(spills, out var spillTypes, out string? typeError))
                return TypedSsaExpressionSchedule.Reject(deadCode, types, typeError!);
            if (!TryBuild(spills, out var roots, out var planned, out string? buildError))
                return TypedSsaExpressionSchedule.Reject(deadCode, types, buildError!);

            var expectedEffects = block.Instructions.Where(instruction => IsLive(instruction)
                    && !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation))
                .Select(instruction => instruction.Id).ToArray();
            var plannedEffects = planned.Where(id =>
                    !SemanticEffectClassifier.IsRemovableIfUnused(instructions[id].Operation))
                .ToArray();
            if (expectedEffects.SequenceEqual(plannedEffects))
            {
                return new TypedSsaExpressionSchedule(deadCode, types, true, "eligible",
                    block, roots, spillTypes, planned);
            }

            bool added = false;
            foreach (var instruction in block.Instructions.Where(instruction => IsLive(instruction)
                && !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation)
                && instruction.Outputs.Count == 1
                && LiveConsumerCount(instruction.Outputs[0]) > 0))
                added |= spills.Add(instruction.Outputs[0]);
            if (!added)
                return TypedSsaExpressionSchedule.Reject(deadCode, types,
                    "typed expression scheduling cannot preserve observable effect order");
        }

        return TypedSsaExpressionSchedule.Reject(deadCode, types,
            "typed expression scheduling did not stabilize");

        bool IsLive(SsaInstruction instruction) =>
            deadCode.LiveInstructionIds.Contains(instruction.Id);

        int LiveConsumerCount(int valueId) => graph.Uses.Count(use =>
            use.ValueId == valueId && IsLiveUse(use));

        bool IsLiveUse(SsaUse use) => use.Kind == SsaUseKind.TerminatorInput
            || use.Kind == SsaUseKind.InstructionInput
            && use.InstructionOrdinal is { } ordinal
            && instructionByLocation.TryGetValue((use.BlockId, ordinal), out var consumer)
            && IsLive(consumer);

        bool TrySpillTypes(
            IReadOnlySet<int> spillValues,
            out IReadOnlyDictionary<int, TypeSignature> result,
            out string? error)
        {
            var mapped = new Dictionary<int, TypeSignature>();
            foreach (int valueId in spillValues.Order())
            {
                if (types.Values[valueId] is not
                    { Kind: SsaCilTypeKind.Exact, Type: { } type })
                {
                    result = mapped;
                    error = $"spill %{valueId} has no exact CIL type ({types.Values[valueId]})";
                    return false;
                }
                mapped[valueId] = type;
            }
            result = mapped;
            error = null;
            return true;
        }

        bool TryBuild(
            IReadOnlySet<int> spillValues,
            out IReadOnlyList<TypedSsaExpressionRoot> resultRoots,
            out IReadOnlyList<int> resultPlan,
            out string? error)
        {
            var roots = new List<TypedSsaExpressionRoot>();
            foreach (var instruction in block.Instructions.Where(IsLive))
            {
                int? output = instruction.Outputs.Count == 1
                    ? instruction.Outputs[0] : null;
                bool effect = !SemanticEffectClassifier.IsRemovableIfUnused(
                    instruction.Operation);
                bool spill = output is { } valueId && spillValues.Contains(valueId);
                int consumers = output is { } consumed ? LiveConsumerCount(consumed) : 0;
                if (spill || effect && (output is null || consumers == 0))
                    roots.Add(new TypedSsaExpressionRoot(instruction.Id,
                        spill ? output : null, effect && output is not null && consumers == 0));
            }

            var planned = new List<int>();
            var emitted = new HashSet<int>();
            var createdSpills = new HashSet<int>();
            foreach (var root in roots)
            {
                var instruction = instructions[root.InstructionId];
                foreach (int input in instruction.Inputs)
                {
                    if (!AppendValue(input, out error))
                    {
                        resultRoots = roots;
                        resultPlan = planned;
                        return false;
                    }
                }
                if (!AppendInstruction(instruction, out error))
                {
                    resultRoots = roots;
                    resultPlan = planned;
                    return false;
                }
                if (root.SpillOutputValueId is { } spill)
                    createdSpills.Add(spill);
            }

            if (block.Terminator is not { } terminator)
            {
                resultRoots = roots;
                resultPlan = planned;
                error = "block has no SSA terminator";
                return false;
            }
            foreach (int input in terminator.Inputs)
            {
                if (!AppendValue(input, out error))
                {
                    resultRoots = roots;
                    resultPlan = planned;
                    return false;
                }
            }

            resultRoots = roots;
            resultPlan = planned;
            error = null;
            return true;

            bool AppendValue(int valueId, out string? appendError)
            {
                appendError = null;
                if (deadCode.ConstantReplacements.ContainsKey(valueId)
                    || graph.Value(valueId).Kind is SsaValueKind.InitialArgument
                        or SsaValueKind.InitialLocal)
                    return true;
                if (spillValues.Contains(valueId))
                {
                    if (createdSpills.Contains(valueId))
                        return true;
                    appendError = $"spill %{valueId} is used before its definition";
                    return false;
                }
                if (graph.Value(valueId).Kind != SsaValueKind.Operation
                    || !definitions.TryGetValue(valueId, out var definition))
                {
                    appendError = $"value %{valueId} has no typed materialization";
                    return false;
                }
                if (!IsLive(definition))
                {
                    appendError = $"definition I{definition.Id} of %{valueId} is not live";
                    return false;
                }
                foreach (int input in definition.Inputs)
                    if (!AppendValue(input, out appendError))
                        return false;
                return AppendInstruction(definition, out appendError);
            }

            bool AppendInstruction(SsaInstruction instruction, out string? appendError)
            {
                appendError = null;
                if (!emitted.Add(instruction.Id))
                {
                    appendError = $"I{instruction.Id} would be emitted more than once";
                    return false;
                }
                planned.Add(instruction.Id);
                return true;
            }
        }
    }
}
