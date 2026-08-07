namespace AgileDevirtualizer.Analysis;

internal sealed record DeadCodeVerificationResult(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class SsaDeadCodeVerifier
{
    public static DeadCodeVerificationResult Verify(DeadCodeResult result)
    {
        var errors = new List<string>();
        var graph = result.Sccp.Graph;
        var executableBlocks = graph.Blocks.Where(IsExecutable).ToArray();
        var instructions = executableBlocks.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var definitions = instructions.Values
            .SelectMany(instruction => instruction.Outputs.Select(output => (output, instruction)))
            .ToDictionary(pair => pair.output, pair => pair.instruction);
        var phis = executableBlocks.SelectMany(block => block.Phis)
            .ToDictionary(phi => phi.Result.Id);

        foreach (int root in result.SideEffectRootIds)
        {
            if (!instructions.TryGetValue(root, out var instruction))
                errors.Add($"side-effect root I{root} is not executable");
            else if (SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation))
                errors.Add($"I{root} was incorrectly classified as a side-effect root");
            if (!result.LiveInstructionIds.Contains(root))
                errors.Add($"side-effect root I{root} is not live");
        }

        foreach (int instructionId in result.LiveInstructionIds)
        {
            if (!instructions.TryGetValue(instructionId, out var instruction))
            {
                errors.Add($"live instruction I{instructionId} is not executable");
                continue;
            }
            foreach (int input in instruction.Inputs)
                VerifyDependency(input, definitions, phis, result, errors,
                    $"I{instructionId}");
            VerifyRequiredPrefixes(instruction, graph.Blocks[instruction.BlockId], result, errors);
        }

        foreach (var block in executableBlocks)
        {
            if (block.Terminator is not { } terminator)
                continue;
            foreach (int input in terminator.Inputs)
                VerifyDependency(input, definitions, phis, result, errors,
                    $"B{block.Id} terminator");
        }

        foreach (var replacement in result.ConstantReplacements)
        {
            int valueId = replacement.Key;
            if (!result.LiveValueIds.Contains(valueId))
                errors.Add($"replacement %{valueId} is not demanded by live code");
            if (result.Sccp.Values[valueId] is not { Kind: SccpValueKind.Constant } lattice
                || !ConstantsEqual(lattice.Constant, replacement.Value))
                errors.Add($"replacement %{valueId} disagrees with SCCP");
            if (!phis.ContainsKey(valueId)
                && (!definitions.TryGetValue(valueId, out var definition)
                    || !SemanticEffectClassifier.CanReplaceWithConstant(definition)))
                errors.Add($"replacement %{valueId} would remove an observable definition");
        }

        return new DeadCodeVerificationResult(errors);

        bool IsExecutable(SsaBlock block) => block.Reachable
            && result.Sccp.ExecutableBlocks.Contains(block.Id);
    }

    private static void VerifyDependency(
        int valueId,
        IReadOnlyDictionary<int, SsaInstruction> definitions,
        IReadOnlyDictionary<int, SsaPhi> phis,
        DeadCodeResult result,
        List<string> errors,
        string consumer)
    {
        if (!result.LiveValueIds.Contains(valueId))
        {
            errors.Add($"{consumer} consumes non-live %{valueId}");
            return;
        }
        if (result.ConstantReplacements.ContainsKey(valueId))
            return;
        var value = result.Sccp.Graph.Value(valueId);
        if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal
            or SsaValueKind.ExceptionObject)
            return;
        if (phis.TryGetValue(valueId, out var phi))
        {
            foreach (var input in phi.Inputs.Where(input => IsExecutableInput(
                input, phi.Result.DefinitionBlockId!.Value, result.Sccp)))
                if (!result.LiveValueIds.Contains(input.ValueId))
                    errors.Add($"{consumer} reaches phi %{valueId} with non-live %{input.ValueId}");
            return;
        }
        if (!definitions.TryGetValue(valueId, out var definition))
            errors.Add($"{consumer} consumes undefined %{valueId}");
        else if (!result.LiveInstructionIds.Contains(definition.Id))
            errors.Add($"{consumer} consumes %{valueId} from dead I{definition.Id}");
    }

    private static void VerifyRequiredPrefixes(
        SsaInstruction instruction,
        SsaBlock block,
        DeadCodeResult result,
        List<string> errors)
    {
        if (instruction.Operation.Code == SemanticOperationCode.Prefix)
            return;
        for (int ordinal = instruction.Ordinal - 1; ordinal >= 0; ordinal--)
        {
            var prefix = block.Instructions[ordinal];
            if (prefix.Operation.Code != SemanticOperationCode.Prefix)
                break;
            if (!result.LiveInstructionIds.Contains(prefix.Id))
                errors.Add($"live I{instruction.Id} lost prefix I{prefix.Id}");
        }
    }

    private static bool IsExecutableInput(
        SsaPhiInput input,
        int targetBlockId,
        SccpResult sccp) => input.Kind == SsaPhiInputKind.MethodEntry
        || sccp.ExecutableEdges.Any(edge => edge.SourceBlockId == input.PredecessorBlockId
            && edge.TargetBlockId == targetBlockId);

    private static bool ConstantsEqual(object? left, object? right)
    {
        if (left is float lf && right is float rf)
            return BitConverter.SingleToInt32Bits(lf) == BitConverter.SingleToInt32Bits(rf);
        if (left is double ld && right is double rd)
            return BitConverter.DoubleToInt64Bits(ld) == BitConverter.DoubleToInt64Bits(rd);
        return Equals(left, right);
    }
}
