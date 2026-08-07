using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Edge-copy emitter after copy propagation and local coalescing. The verified expression schedule
/// forwards single-use values on the evaluation stack, while each phi congruence class receives one
/// typed location. Edge copies remain explicit in the plan; copies coalesced to the same location
/// disappear during emission.
/// </summary>
internal static class CoalescedSsaEdgeEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        SsaEdgeCopyPlan edges,
        SsaPhiLoweringPlan schedule,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!edges.Eligible || !schedule.Eligible)
            throw new InvalidOperationException("coalesced edge emission requires two valid plans");
        if (!ReferenceEquals(edges.DeadCode.Sccp.Graph, schedule.DeadCode.Sccp.Graph)
            || !edges.BlockOrder.SequenceEqual(schedule.BlockOrder))
            throw new InvalidOperationException("edge and expression plans do not match");

        var installed = target.CilMethodBody;
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
        foreach (var phiClass in schedule.Classes)
        {
            if (phiClass.ReusedVariable is { Kind: SsaVariableKind.Argument } argument)
                classArguments[phiClass.Id] = Argument(target, argument.Index);
            else
                classLocals[phiClass.Id] = phiClass.ReusedVariable is { } reused
                    ? Slot(reused, locals, temps)
                    : Declare(body, importer, phiClass.Type);
        }
        var spillLocals = schedule.SpillTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var labels = edges.BlockOrder.ToDictionary(id => id, _ => new CilInstructionLabel());
        var splitLabels = edges.EdgeCopies
            .Where(copy => copy.Placement == SsaEdgeCopyPlacement.SplitBlock)
            .ToDictionary(copy => copy.Edge!, _ => new CilInstructionLabel());
        var starts = new Dictionary<int, int>();
        var splitStarts = new Dictionary<ControlFlowEdge, int>();
        var ssa = edges.DeadCode.Sccp.Graph;
        var instructions = ssa.Blocks.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        var definitions = instructions.Values
            .SelectMany(instruction => instruction.Outputs.Select(value => (value, instruction)))
            .ToDictionary(pair => pair.value, pair => pair.instruction);

        var entry = edges.EdgeCopies.SingleOrDefault(copy =>
            copy.Placement == SsaEdgeCopyPlacement.MethodEntry);
        if (entry is not null)
            EmitParallelCopies(entry.Copies);

        for (int position = 0; position < edges.BlockOrder.Count; position++)
        {
            int blockId = edges.BlockOrder[position];
            starts[blockId] = body.Instructions.Count;
            foreach (var copy in edges.EdgeCopies.Where(copy =>
                copy.Placement == SsaEdgeCopyPlacement.TargetEntry
                && copy.TargetBlockId == blockId))
                EmitParallelCopies(copy.Copies);

            var blockPlan = schedule.Blocks[blockId];
            var emitted = new HashSet<int>();
            var emittedOrder = new List<int>();
            foreach (var root in blockPlan.Roots)
            {
                var instruction = instructions[root.InstructionId];
                foreach (int input in instruction.Inputs)
                    EmitValue(input, emitted, emittedOrder);
                EmitInstruction(instruction, emitted, emittedOrder);
                if (root.SpillValueId is { } spill)
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                        spillLocals[spill]));
                else if (root.ClassId is { } classId)
                    StoreClass(classId);
                else if (root.DiscardResult)
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
            }

            var ssaBlock = ssa.Blocks[blockId];
            foreach (int input in ssaBlock.Terminator!.Inputs)
                EmitValue(input, emitted, emittedOrder);
            foreach (var copy in edges.EdgeCopies.Where(copy =>
                copy.Placement == SsaEdgeCopyPlacement.SourceExit
                && copy.SourceBlockId == blockId))
                EmitParallelCopies(copy.Copies);
            if (!blockPlan.PlannedInstructionIds.SequenceEqual(emittedOrder))
                throw new InvalidOperationException($"B{blockId} violated its expression schedule");

            int? next = position + 1 < edges.BlockOrder.Count
                ? edges.BlockOrder[position + 1] : null;
            EmitTerminator(graph.Blocks[blockId], next);
        }

        foreach (var copy in edges.EdgeCopies.Where(copy =>
            copy.Placement == SsaEdgeCopyPlacement.SplitBlock))
        {
            var edge = copy.Edge!;
            splitStarts[edge] = body.Instructions.Count;
            EmitParallelCopies(copy.Copies);
            body.Instructions.Add(new CilInstruction(CilOpCodes.Br, labels[edge.TargetBlockId]));
        }

        if (body.Instructions.Count == 0)
            throw new InvalidOperationException("coalesced edge emitter produced an empty body");
        foreach (var pair in starts)
            labels[pair.Key].Instruction = body.Instructions[
                Math.Min(pair.Value, body.Instructions.Count - 1)];
        foreach (var pair in splitStarts)
            splitLabels[pair.Key].Instruction = body.Instructions[pair.Value];

        CilAggregateStringFolder.Fold(module, body);
        CilLocalCleanup.Run(body);
        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        body.Instructions.CalculateOffsets();
        body.VerifyLabels(calculateOffsets: false);
        body.ComputeMaxStack();
        CilTypeSafetyValidator.Validate(body);
        owner.CilMethodBody = null;
        if (!ReferenceEquals(target.CilMethodBody, installed))
            throw new InvalidOperationException("coalesced shadow emitter changed the target body");
        return body;

        void EmitValue(int valueId, HashSet<int>? emitted = null, List<int>? order = null)
        {
            if (edges.DeadCode.ConstantReplacements.TryGetValue(valueId, out object? constant))
            {
                body.Instructions.Add(SsaConstantEmitter.Emit(constant));
                return;
            }
            if (schedule.ValueClass.TryGetValue(valueId, out int classId))
            {
                body.Instructions.Add(classArguments.TryGetValue(classId, out var argument)
                    ? new CilInstruction(CilOpCodes.Ldarg, argument)
                    : new CilInstruction(CilOpCodes.Ldloc, classLocals[classId]));
                return;
            }
            if (spillLocals.TryGetValue(valueId, out var spill))
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, spill));
                return;
            }
            var value = ssa.Value(valueId);
            if (value.Kind == SsaValueKind.InitialArgument)
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldarg,
                    Argument(target, value.Variable!.Value.Index)));
                return;
            }
            if (value.Kind == SsaValueKind.InitialLocal)
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc,
                    Slot(value.Variable!.Value, locals, temps)));
                return;
            }
            if (value.Kind != SsaValueKind.Operation || !definitions.TryGetValue(valueId,
                out var definition) || emitted is null || order is null)
                throw new InvalidOperationException($"SSA value %{valueId} has no location");
            foreach (int input in definition.Inputs)
                EmitValue(input, emitted, order);
            EmitInstruction(definition, emitted, order);
        }

        void EmitInstruction(SsaInstruction instruction, HashSet<int> emitted, List<int> order)
        {
            if (!emitted.Add(instruction.Id))
                throw new InvalidOperationException($"I{instruction.Id} emitted twice");
            order.Add(instruction.Id);
            body.Instructions.Add(SemanticCfgEmitter.LowerOperation(
                module, importer, target, locals, temps, instruction.Operation));
        }

        void EmitParallelCopies(IReadOnlyList<SsaTypedPhiCopy> copies)
        {
            var remaining = copies.Where(copy => !SameLocation(copy.SourceValueId,
                copy.PhiValueId)).ToArray();
            foreach (var copy in remaining)
                EmitValue(copy.SourceValueId);
            for (int index = remaining.Length - 1; index >= 0; index--)
                StoreValueClass(remaining[index].PhiValueId);
        }

        bool SameLocation(int source, int destination) =>
            schedule.ValueClass.TryGetValue(source, out int sourceClass)
            && schedule.ValueClass.TryGetValue(destination, out int destinationClass)
            && sourceClass == destinationClass;

        void StoreValueClass(int valueId)
        {
            if (!schedule.ValueClass.TryGetValue(valueId, out int classId))
                throw new InvalidOperationException($"phi %{valueId} has no coalesced class");
            StoreClass(classId);
        }

        void StoreClass(int classId)
        {
            if (classArguments.ContainsKey(classId))
                throw new InvalidOperationException($"cannot store into argument-hosted C{classId}");
            body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc, classLocals[classId]));
        }

        void EmitTerminator(BasicBlock block, int? nextBlockId)
        {
            var normal = edges.DeadCode.Sccp.ExecutableEdges.Where(edge =>
                edge.SourceBlockId == block.Id
                && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)).ToArray();
            CilInstructionLabel Target(ControlFlowEdge edge) =>
                splitLabels.TryGetValue(edge, out var split) ? split : labels[edge.TargetBlockId];
            bool IsNext(ControlFlowEdge edge) => !splitLabels.ContainsKey(edge)
                && edge.TargetBlockId == nextBlockId;
            switch (block.Terminator.Kind)
            {
                case SemanticTerminatorKind.FallThrough:
                case SemanticTerminatorKind.Branch:
                    var successor = normal.Single();
                    if (!IsNext(successor))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(successor)));
                    break;
                case SemanticTerminatorKind.Conditional:
                    var taken = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.ConditionalTaken);
                    var fall = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.ConditionalFallThrough);
                    body.Instructions.Add(new CilInstruction(SemanticCilLowerer.Lower(
                        block.Terminator, false), Target(taken)));
                    if (!IsNext(fall))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(fall)));
                    break;
                case SemanticTerminatorKind.Switch:
                    var table = new ICilLabel[block.Terminator.TargetInstructionIndices.Count];
                    foreach (var edge in normal.Where(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchCase))
                        table[edge.SwitchCaseIndex!.Value] = Target(edge);
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Switch, table.ToList()));
                    var defaultEdge = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchDefault);
                    if (!IsNext(defaultEdge))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br,
                            Target(defaultEdge)));
                    break;
                default:
                    body.Instructions.Add(new CilInstruction(SemanticCilLowerer.Lower(
                        block.Terminator, false)));
                    break;
            }
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

    private static CilLocalVariable Slot(SsaVariableSlot variable,
        CilLocalVariable[] locals, CilLocalVariable[] temps) =>
        (variable.Temporary ? temps : locals)[variable.Index];

    private static Parameter Argument(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self : target.Parameters[vmIndex - 1];
        return target.Parameters[vmIndex];
    }
}
