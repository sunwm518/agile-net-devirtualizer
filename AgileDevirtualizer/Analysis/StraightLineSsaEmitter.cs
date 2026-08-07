using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// First genuine SSA-to-CIL lowering stage. It emits verified single-block expression trees and
/// deliberately allocates no SSA spill locals. More complex graphs remain on the semantic CFG
/// emitter until typed spills and phi edge copies are available.
/// </summary>
internal static class StraightLineSsaEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SsaExpressionSchedule schedule,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!schedule.Eligible || schedule.Block is null)
            throw new InvalidOperationException(
                $"SSA expression schedule is not eligible: {schedule.Reason}");
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
        var body = new CilMethodBody
        {
            InitializeLocals = decoded.Locals.Count > 0 || tempLocalTypes.Count > 0,
        };
        owner.CilMethodBody = body;
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);
        var emitted = new HashSet<int>();
        var emittedOrder = new List<int>();

        foreach (var root in schedule.Roots)
        {
            var instruction = instructions[root.InstructionId];
            foreach (int input in instruction.Inputs)
                EmitValue(input);
            EmitInstruction(instruction);
            if (root.DiscardResult)
                body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
        }

        foreach (int input in block.Terminator!.Inputs)
            EmitValue(input);
        body.Instructions.Add(new CilInstruction(
            SemanticCilLowerer.Lower(block.Terminator.Terminator, isLeave: false)));

        if (!schedule.PlannedInstructionIds.SequenceEqual(emittedOrder))
            throw new InvalidOperationException(
                "SSA emitter did not follow the verified expression schedule");
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
            throw new InvalidOperationException("SSA shadow emitter changed the target body");
        return body;

        void EmitValue(int valueId)
        {
            if (schedule.DeadCode.ConstantReplacements.TryGetValue(valueId, out var constant))
            {
                body.Instructions.Add(SsaConstantEmitter.Emit(constant));
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
                        $"SSA value %{valueId} requires a spill or phi lowering");
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
