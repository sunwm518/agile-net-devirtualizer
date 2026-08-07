using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>Emits a verified one-block SSA expression schedule with exact typed spills.</summary>
internal static class TypedStraightLineSsaEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        TypedSsaExpressionSchedule schedule,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!schedule.Eligible || schedule.Block is null)
            throw new InvalidOperationException(
                $"typed SSA schedule is not eligible: {schedule.Reason}");
        var originalBody = target.CilMethodBody;
        var graph = schedule.DeadCode.Sccp.Graph;
        var block = schedule.Block;
        var instructions = block.Instructions.ToDictionary(instruction => instruction.Id);
        var definitions = block.Instructions
            .SelectMany(instruction => instruction.Outputs.Select(valueId =>
                (ValueId: valueId, Instruction: instruction)))
            .ToDictionary(pair => pair.ValueId, pair => pair.Instruction);
        var owner = new MethodDefinition(target.Name, target.Attributes,
            target.Signature ?? throw new InvalidOperationException("target has no signature"),
            verify: false);
        var body = new CilMethodBody { InitializeLocals = true };
        owner.CilMethodBody = body;
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);
        var spillLocals = schedule.SpillTypes.ToDictionary(pair => pair.Key, pair =>
        {
            var local = new CilLocalVariable(importer.ImportTypeSignature(pair.Value));
            body.LocalVariables.Add(local);
            return local;
        });
        var emitted = new HashSet<int>();
        var emittedOrder = new List<int>();
        var createdSpills = new HashSet<int>();

        foreach (var root in schedule.Roots)
        {
            var instruction = instructions[root.InstructionId];
            foreach (int input in instruction.Inputs)
                EmitValue(input);
            EmitInstruction(instruction);
            if (root.SpillOutputValueId is { } spill)
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                    spillLocals[spill]));
                createdSpills.Add(spill);
            }
            else if (root.DiscardResult)
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
            }
        }

        foreach (int input in block.Terminator!.Inputs)
            EmitValue(input);
        body.Instructions.Add(new CilInstruction(
            SemanticCilLowerer.Lower(block.Terminator.Terminator, isLeave: false)));

        if (!schedule.PlannedInstructionIds.SequenceEqual(emittedOrder))
            throw new InvalidOperationException(
                "typed SSA emitter did not follow the verified schedule");
        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        body.Instructions.CalculateOffsets();
        body.VerifyLabels(calculateOffsets: false);
        body.ComputeMaxStack();
        CilTypeSafetyValidator.Validate(body);
        owner.CilMethodBody = null;
        if (!ReferenceEquals(target.CilMethodBody, originalBody))
            throw new InvalidOperationException("typed SSA shadow emitter changed the target body");
        return body;

        void EmitValue(int valueId)
        {
            if (schedule.DeadCode.ConstantReplacements.TryGetValue(valueId, out var constant))
            {
                body.Instructions.Add(SsaConstantEmitter.Emit(constant));
                return;
            }
            if (spillLocals.TryGetValue(valueId, out var spill))
            {
                if (!createdSpills.Contains(valueId))
                    throw new InvalidOperationException($"spill %{valueId} was not initialized");
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, spill));
                return;
            }
            var value = graph.Value(valueId);
            switch (value.Kind)
            {
                case SsaValueKind.InitialArgument:
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Ldarg,
                        Argument(target, value.Variable!.Value.Index)));
                    return;
                case SsaValueKind.InitialLocal:
                    var variable = value.Variable!.Value;
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc,
                        variable.Temporary ? temps[variable.Index] : locals[variable.Index]));
                    return;
                case SsaValueKind.Operation:
                    if (!definitions.TryGetValue(valueId, out var definition))
                        throw new InvalidOperationException($"SSA value %{valueId} has no definition");
                    foreach (int input in definition.Inputs)
                        EmitValue(input);
                    EmitInstruction(definition);
                    return;
                default:
                    throw new InvalidOperationException(
                        $"SSA value %{valueId} requires phi lowering");
            }
        }

        void EmitInstruction(SsaInstruction instruction)
        {
            if (!emitted.Add(instruction.Id))
                throw new InvalidOperationException($"SSA instruction I{instruction.Id} was reused");
            emittedOrder.Add(instruction.Id);
            body.Instructions.Add(SemanticCfgEmitter.LowerOperation(
                module, importer, target, locals, temps, instruction.Operation));
        }
    }

    private static Parameter Argument(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self : target.Parameters[vmIndex - 1];
        return target.Parameters[vmIndex];
    }
}
