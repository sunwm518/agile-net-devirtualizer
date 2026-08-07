using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Emits a phi-free multi-block body from a verified phi-lowering plan. Congruence-class slots carry
/// every value across a block boundary, so the evaluation stack is empty at each boundary and no edge
/// is split. The body is owned by a detached synthetic method and never replaces the target body.
/// </summary>
internal static class TypedSsaCfgEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        SsaPhiLoweringPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!plan.Eligible)
            throw new InvalidOperationException($"phi lowering plan is not eligible: {plan.Reason}");
        if (!ReferenceEquals(plan.DeadCode.Sccp.Graph.Source, graph))
            throw new InvalidOperationException("phi lowering plan belongs to a different CFG");
        if (decoded.ExceptionHandlers.Count != 0 || graph.ExceptionRegions.Count != 0)
            throw new InvalidOperationException("phi lowering does not model exception regions");

        var originalBody = target.CilMethodBody;
        var ssa = plan.DeadCode.Sccp.Graph;
        var owner = new MethodDefinition(target.Name, target.Attributes,
            target.Signature ?? throw new InvalidOperationException("target has no signature"),
            verify: false);
        var body = new CilMethodBody { InitializeLocals = true };
        owner.CilMethodBody = body;
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);
        var classLocals = new Dictionary<int, CilLocalVariable>();
        var classArguments = new Dictionary<int, Parameter>();
        foreach (var phiClass in plan.Classes)
        {
            if (phiClass.ReusedVariable is { Kind: SsaVariableKind.Argument } argument)
                classArguments[phiClass.Id] = Argument(target, argument.Index);
            else
                classLocals[phiClass.Id] = phiClass.ReusedVariable is { } reused
                    ? Slot(reused, locals, temps)
                    : Declare(body, importer, phiClass.Type);
        }
        var spillLocals = plan.SpillTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var labels = plan.BlockOrder.ToDictionary(id => id, _ => new CilInstructionLabel());
        var starts = new Dictionary<int, int>();
        var instructions = ssa.Blocks.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var definitions = ssa.Blocks.SelectMany(block => block.Instructions)
            .SelectMany(instruction => instruction.Outputs.Select(value => (value, instruction)))
            .ToDictionary(pair => pair.value, pair => pair.instruction);

        foreach (var store in plan.EntryStores)
            EmitClassStore(store);

        for (int position = 0; position < plan.BlockOrder.Count; position++)
        {
            int blockId = plan.BlockOrder[position];
            var blockPlan = plan.Blocks[blockId];
            var ssaBlock = ssa.Blocks[blockId];
            starts[blockId] = body.Instructions.Count;
            var emittedOrder = new List<int>();

            foreach (var root in blockPlan.Roots)
            {
                var instruction = instructions[root.InstructionId];
                foreach (int input in instruction.Inputs)
                    EmitValue(input);
                EmitInstruction(instruction);
                if (root.SpillValueId is { } spill)
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                        spillLocals[spill]));
                else if (root.ClassId is { } classId)
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                        classArguments.ContainsKey(classId)
                            ? throw new InvalidOperationException(
                                $"C{classId} is hosted in an argument and must never be stored")
                            : classLocals[classId]));
                else if (root.DiscardResult)
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
            }

            var terminator = ssaBlock.Terminator
                ?? throw new InvalidOperationException($"B{blockId} has no SSA terminator");
            foreach (int input in terminator.Inputs)
                EmitValue(input);
            foreach (var store in blockPlan.ExitStores)
                EmitClassStore(store);

            if (!blockPlan.PlannedInstructionIds.SequenceEqual(emittedOrder))
                throw new InvalidOperationException(
                    $"B{blockId} emission did not follow the verified schedule");
            int? next = position + 1 < plan.BlockOrder.Count ? plan.BlockOrder[position + 1] : null;
            foreach (var emitted in SsaTerminatorLowerer.Lower(
                graph.Blocks[blockId], graph, labels, next))
                body.Instructions.Add(emitted);
            continue;

            void EmitInstruction(SsaInstruction instruction)
            {
                emittedOrder.Add(instruction.Id);
                body.Instructions.Add(SemanticCfgEmitter.LowerOperation(
                    module, importer, target, locals, temps, instruction.Operation));
            }

            void EmitValue(int valueId)
            {
                if (plan.DeadCode.ConstantReplacements.TryGetValue(valueId, out object? constant))
                {
                    body.Instructions.Add(SsaConstantEmitter.Emit(constant));
                    return;
                }
                if (plan.ValueClass.TryGetValue(valueId, out int classId))
                {
                    body.Instructions.Add(classArguments.TryGetValue(classId, out var hosted)
                        ? new CilInstruction(CilOpCodes.Ldarg, hosted)
                        : new CilInstruction(CilOpCodes.Ldloc, classLocals[classId]));
                    return;
                }
                if (spillLocals.TryGetValue(valueId, out var spill))
                {
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, spill));
                    return;
                }
                var value = ssa.Value(valueId);
                switch (value.Kind)
                {
                    case SsaValueKind.InitialArgument:
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldarg,
                            Argument(target, value.Variable!.Value.Index)));
                        return;
                    case SsaValueKind.InitialLocal:
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc,
                            Slot(value.Variable!.Value, locals, temps)));
                        return;
                    case SsaValueKind.Operation:
                        if (!definitions.TryGetValue(valueId, out var definition))
                            throw new InvalidOperationException(
                                $"SSA value %{valueId} has no definition");
                        foreach (int input in definition.Inputs)
                            EmitValue(input);
                        EmitInstruction(definition);
                        return;
                    default:
                        throw new InvalidOperationException(
                            $"SSA value %{valueId} ({value.Kind}) has no lowered location");
                }
            }
        }

        if (body.Instructions.Count == 0)
            throw new InvalidOperationException("phi lowering emitted an empty method");
        for (int position = plan.BlockOrder.Count - 1; position >= 0; position--)
        {
            int blockId = plan.BlockOrder[position];
            labels[blockId].Instruction = body.Instructions[
                Math.Min(starts[blockId], body.Instructions.Count - 1)];
        }

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
            throw new InvalidOperationException("phi lowering shadow emitter changed the target body");
        return body;

        void EmitClassStore(SsaClassStore store)
        {
            if (classArguments.ContainsKey(store.ClassId))
                throw new InvalidOperationException(
                    $"C{store.ClassId} is hosted in an argument and must never be stored");
            switch (store.Source)
            {
                case SsaClassStoreSource.Constant:
                    body.Instructions.Add(SsaConstantEmitter.Emit(store.Constant));
                    break;
                case SsaClassStoreSource.InitialVariable:
                    var variable = store.Variable
                        ?? throw new InvalidOperationException("initial store has no variable");
                    body.Instructions.Add(variable.Kind == SsaVariableKind.Argument
                        ? new CilInstruction(CilOpCodes.Ldarg, Argument(target, variable.Index))
                        : new CilInstruction(CilOpCodes.Ldloc, Slot(variable, locals, temps)));
                    break;
                default:
                    throw new InvalidOperationException(
                        $"class store source {store.Source} is not emittable");
            }
            body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                classLocals[store.ClassId]));
        }
    }

    private static CilLocalVariable Declare(
        CilMethodBody body,
        ReferenceImporter importer,
        TypeSignature type)
    {
        var local = new CilLocalVariable(importer.ImportTypeSignature(type));
        body.LocalVariables.Add(local);
        return local;
    }

    private static CilLocalVariable Slot(
        SsaVariableSlot variable,
        CilLocalVariable[] locals,
        CilLocalVariable[] temps)
    {
        if (variable.Kind != SsaVariableKind.Local)
            throw new InvalidOperationException($"{variable} is not a local slot");
        var set = variable.Temporary ? temps : locals;
        if (variable.Index < 0 || variable.Index >= set.Length)
            throw new InvalidOperationException($"{variable} is outside the declared local set");
        return set[variable.Index];
    }

    private static Parameter Argument(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self : target.Parameters[vmIndex - 1];
        return target.Parameters[vmIndex];
    }
}
