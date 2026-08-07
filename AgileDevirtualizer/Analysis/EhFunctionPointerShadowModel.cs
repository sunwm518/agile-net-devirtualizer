using AsmResolver.DotNet;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// A verifier-sensitive function pointer that must stay on the evaluation stack. It is emitted at
/// its sole native-int consumer instead of being serialized through an IntPtr local.
/// </summary>
internal sealed record EhFunctionPointerRematerialization(
    int ValueId,
    int DefinitionInstructionId,
    int ConsumerInstructionId,
    int ConsumerInputIndex,
    SemanticOperation Operation);

internal sealed record EhFunctionPointerShadowModel(
    bool Valid,
    string Reason,
    IReadOnlyDictionary<int, EhFunctionPointerRematerialization> Values);

/// <summary>
/// Recognizes the canonical direct-function-pointer shape without relying on method names or
/// metadata tokens. Virtual pointers and values that cross an instruction, block, phi or EH edge
/// fail closed because rematerializing those forms could change receiver or exception semantics.
/// </summary>
internal static class EhFunctionPointerShadowModelBuilder
{
    public static EhFunctionPointerShadowModel Build(
        SsaGraph graph,
        EhSsaEmissionClosure closure)
    {
        var instructions = graph.Blocks.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var instructionByLocation = instructions.Values.ToDictionary(
            instruction => (instruction.BlockId, instruction.Ordinal));
        var result = new Dictionary<int, EhFunctionPointerRematerialization>();

        foreach (var definition in instructions.Values.Where(instruction =>
            closure.InstructionIds.Contains(instruction.Id)
            && instruction.Operation.Code == SemanticOperationCode.LoadFunctionPointer))
        {
            if (definition.Operation.Semantics.Dispatch != SemanticDispatchKind.Direct)
                return Invalid($"I{definition.Id} is not a direct ldftn");
            if (definition.Inputs.Count != 0 || definition.Outputs.Count != 1)
                return Invalid($"I{definition.Id} does not have the direct ldftn stack shape");
            int valueId = definition.Outputs[0];
            if (!closure.ValueIds.Contains(valueId)
                || closure.Constants.ContainsKey(valueId))
                return Invalid($"function pointer %{valueId} is not a live operation value");
            if (definition.Operation.Operand is not IMethodDescriptor
                { Signature: not null })
                return Invalid($"function pointer %{valueId} has no exact method signature");

            var uses = graph.Uses.Where(use => use.ValueId == valueId)
                .Where(use => IsLiveUse(use, graph, closure, instructionByLocation))
                .ToArray();
            if (uses.Length != 1 || uses[0].Kind != SsaUseKind.InstructionInput
                || uses[0].InstructionOrdinal is not { } consumerOrdinal
                || !instructionByLocation.TryGetValue(
                    (uses[0].BlockId, consumerOrdinal), out var consumer))
                return Invalid($"function pointer %{valueId} does not have one instruction use");
            if (consumer.BlockId != definition.BlockId
                || consumer.Ordinal != definition.Ordinal + 1)
                return Invalid($"function pointer %{valueId} crosses an instruction or block boundary");

            var inputIndexes = consumer.Inputs.Select((input, index) => (input, index))
                .Where(pair => pair.input == valueId).Select(pair => pair.index).ToArray();
            if (inputIndexes.Length != 1)
                return Invalid($"function pointer %{valueId} is not consumed exactly once");
            int inputIndex = inputIndexes[0];
            if (consumer.Operation.Code != SemanticOperationCode.NewObject
                || consumer.Operation.Operand is not IMethodDescriptor constructor
                || constructor.Signature is not { } signature
                || signature.ParameterTypes.Count != consumer.Inputs.Count
                || !IsNativeInt(signature.ParameterTypes[inputIndex].FullName))
                return Invalid($"function pointer %{valueId} is not consumed by a native-int constructor parameter");

            result[valueId] = new EhFunctionPointerRematerialization(valueId,
                definition.Id, consumer.Id, inputIndex, definition.Operation);
        }

        return new EhFunctionPointerShadowModel(true, "valid", result);

        EhFunctionPointerShadowModel Invalid(string reason) =>
            new(false, reason, result);
    }

    private static bool IsLiveUse(
        SsaUse use,
        SsaGraph graph,
        EhSsaEmissionClosure closure,
        IReadOnlyDictionary<(int BlockId, int Ordinal), SsaInstruction> instructions) =>
        use.Kind switch
        {
            SsaUseKind.InstructionInput => use.InstructionOrdinal is { } ordinal
                && instructions.TryGetValue((use.BlockId, ordinal), out var consumer)
                && closure.InstructionIds.Contains(consumer.Id),
            SsaUseKind.TerminatorInput => graph.Blocks[use.BlockId].Reachable
                && closure.ValueIds.Contains(use.ValueId),
            SsaUseKind.PhiInput => graph.Blocks[use.BlockId].Phis.Any(phi =>
                closure.ValueIds.Contains(phi.Result.Id)
                && phi.Inputs.Any(input => input.ValueId == use.ValueId)),
            _ => false,
        };

    private static bool IsNativeInt(string fullName) =>
        fullName is "System.IntPtr" or "System.UIntPtr";
}
