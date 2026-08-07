namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaEmissionClosure(
    bool Valid,
    string Reason,
    IReadOnlySet<int> InstructionIds,
    IReadOnlySet<int> ValueIds,
    IReadOnlyDictionary<int, object?> Constants);

/// <summary>
/// Extends ordinary DCE liveness with every source-variable store. EH can observe a local at any
/// preceding throwing operation, so keeping only the store selected by a block-exit phi is unsound.
/// Dependencies are recovered transitively from SSA and pure constants remain foldable.
/// </summary>
internal static class EhSsaEmissionClosureBuilder
{
    public static EhSsaEmissionClosure Build(DeadCodeResult deadCode)
    {
        var graph = deadCode.Sccp.Graph;
        var executable = graph.Blocks.Where(block => block.Reachable
            && deadCode.Sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        var instructions = executable.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var definitions = instructions.Values
            .SelectMany(instruction => instruction.Outputs.Select(output => (output, instruction)))
            .ToDictionary(pair => pair.output, pair => pair.instruction);
        var phis = executable.SelectMany(block => block.Phis)
            .ToDictionary(phi => phi.Result.Id);
        var instructionIds = new HashSet<int>();
        var valueIds = new HashSet<int>();
        var constants = new Dictionary<int, object?>();
        var instructionQueue = new Queue<int>(deadCode.LiveInstructionIds);
        var valueQueue = new Queue<int>(deadCode.LiveValueIds);

        foreach (var instruction in instructions.Values.Where(instruction =>
            SsaStackSemantics.ForOperation(instruction.Operation).Behavior
                == SsaOperationBehavior.StoreVariable))
            instructionQueue.Enqueue(instruction.Id);

        while (instructionQueue.Count > 0 || valueQueue.Count > 0)
        {
            while (instructionQueue.Count > 0)
            {
                int id = instructionQueue.Dequeue();
                if (!instructionIds.Add(id))
                    continue;
                if (!instructions.TryGetValue(id, out var instruction))
                    return Invalid($"required I{id} is not executable");
                foreach (int input in instruction.Inputs)
                    valueQueue.Enqueue(input);
                MarkPrefixes(instruction, graph.Blocks[instruction.BlockId], instructionQueue);
            }

            if (valueQueue.Count == 0)
                continue;
            int valueId = valueQueue.Dequeue();
            if (!valueIds.Add(valueId))
                continue;
            if (CanMaterializeConstant(valueId, out object? constant))
            {
                constants[valueId] = constant;
                continue;
            }
            var value = graph.Value(valueId);
            if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal
                or SsaValueKind.ExceptionObject)
                continue;
            if (phis.TryGetValue(valueId, out var phi))
            {
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, deadCode.Sccp))
                    valueQueue.Enqueue(input.ValueId);
                continue;
            }
            if (value.Kind == SsaValueKind.Operation
                && definitions.TryGetValue(valueId, out var definition))
            {
                instructionQueue.Enqueue(definition.Id);
                continue;
            }
            return Invalid($"required %{valueId} ({value.Kind}) has no executable definition");
        }

        return new EhSsaEmissionClosure(true, "valid", instructionIds,
            valueIds, constants);

        bool CanMaterializeConstant(int valueId, out object? constant)
        {
            if (deadCode.Sccp.Values[valueId] is not
                { Kind: SccpValueKind.Constant } lattice)
            {
                constant = null;
                return false;
            }
            bool replaceable = phis.ContainsKey(valueId)
                || definitions.TryGetValue(valueId, out var definition)
                && SemanticEffectClassifier.CanReplaceWithConstant(definition);
            constant = lattice.Constant;
            return replaceable;
        }

        EhSsaEmissionClosure Invalid(string reason) => new(false, reason,
            instructionIds, valueIds, constants);
    }

    private static void MarkPrefixes(
        SsaInstruction instruction,
        SsaBlock block,
        Queue<int> queue)
    {
        for (int ordinal = instruction.Ordinal - 1; ordinal >= 0; ordinal--)
        {
            var prefix = block.Instructions[ordinal];
            if (prefix.Operation.Code != SemanticOperationCode.Prefix)
                break;
            queue.Enqueue(prefix.Id);
        }
    }
}
