using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Conservative multi-block SSA shadow emitter. Phi values and operation results use exact typed
/// locals; phi assignments are emitted in parallel on their owning edge. Critical edges are
/// retargeted through synthetic blocks, making edge-specific assignments unambiguous.
/// </summary>
internal static class TypedSsaEdgeEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        SsaEdgeCopyPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!plan.Eligible)
            throw new InvalidOperationException($"edge-copy plan is not eligible: {plan.Reason}");
        if (!ReferenceEquals(plan.DeadCode.Sccp.Graph.Source, graph))
            throw new InvalidOperationException("edge-copy plan belongs to a different CFG");
        if (decoded.ExceptionHandlers.Count != 0 || graph.ExceptionRegions.Count != 0)
            throw new InvalidOperationException("edge-copy emission does not model EH");

        var installed = target.CilMethodBody;
        var owner = new MethodDefinition(target.Name, target.Attributes,
            target.Signature ?? throw new InvalidOperationException("target has no signature"),
            verify: false);
        var body = new CilMethodBody { InitializeLocals = true };
        owner.CilMethodBody = body;
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);
        var phiLocals = plan.PhiTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var spillLocals = plan.OperationSpillTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var labels = plan.BlockOrder.ToDictionary(id => id, _ => new CilInstructionLabel());
        var splitLabels = plan.EdgeCopies
            .Where(copy => copy.Placement == SsaEdgeCopyPlacement.SplitBlock)
            .ToDictionary(copy => copy.Edge!, _ => new CilInstructionLabel());
        var starts = new Dictionary<int, int>();
        var splitStarts = new Dictionary<ControlFlowEdge, int>();
        var ssa = plan.DeadCode.Sccp.Graph;

        var entry = plan.EdgeCopies.SingleOrDefault(copy =>
            copy.Placement == SsaEdgeCopyPlacement.MethodEntry);
        if (entry is not null)
            EmitParallelCopies(entry.Copies);

        for (int position = 0; position < plan.BlockOrder.Count; position++)
        {
            int blockId = plan.BlockOrder[position];
            starts[blockId] = body.Instructions.Count;
            foreach (var copy in plan.EdgeCopies.Where(copy =>
                copy.Placement == SsaEdgeCopyPlacement.TargetEntry
                && copy.TargetBlockId == blockId))
                EmitParallelCopies(copy.Copies);

            var block = ssa.Blocks[blockId];
            foreach (var instruction in block.Instructions.Where(instruction =>
                plan.DeadCode.LiveInstructionIds.Contains(instruction.Id)))
            {
                foreach (int input in instruction.Inputs)
                    EmitValue(input);
                body.Instructions.Add(SemanticCfgEmitter.LowerOperation(
                    module, importer, target, locals, temps, instruction.Operation));
                if (instruction.Outputs.Count == 1)
                {
                    int output = instruction.Outputs[0];
                    if (spillLocals.TryGetValue(output, out var spill))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc, spill));
                    else
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
                }
            }

            var terminator = block.Terminator
                ?? throw new InvalidOperationException($"B{blockId} has no SSA terminator");
            foreach (int input in terminator.Inputs)
                EmitValue(input);
            foreach (var copy in plan.EdgeCopies.Where(copy =>
                copy.Placement == SsaEdgeCopyPlacement.SourceExit
                && copy.SourceBlockId == blockId))
                EmitParallelCopies(copy.Copies);

            int? next = position + 1 < plan.BlockOrder.Count
                ? plan.BlockOrder[position + 1] : null;
            EmitTerminator(graph.Blocks[blockId], next);
        }

        foreach (var copy in plan.EdgeCopies.Where(copy =>
            copy.Placement == SsaEdgeCopyPlacement.SplitBlock))
        {
            var edge = copy.Edge!;
            splitStarts[edge] = body.Instructions.Count;
            EmitParallelCopies(copy.Copies);
            body.Instructions.Add(new CilInstruction(CilOpCodes.Br, labels[edge.TargetBlockId]));
        }

        if (body.Instructions.Count == 0)
            throw new InvalidOperationException("edge-copy emitter produced an empty body");
        foreach (var pair in starts.OrderByDescending(pair => pair.Key))
            labels[pair.Key].Instruction = body.Instructions[
                Math.Min(pair.Value, body.Instructions.Count - 1)];
        foreach (var pair in splitStarts)
            splitLabels[pair.Key].Instruction = body.Instructions[pair.Value];

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
            throw new InvalidOperationException("edge-copy shadow emitter changed the target body");
        return body;

        void EmitValue(int valueId)
        {
            if (plan.DeadCode.ConstantReplacements.TryGetValue(valueId, out object? constant))
            {
                body.Instructions.Add(SsaConstantEmitter.Emit(constant));
                return;
            }
            if (phiLocals.TryGetValue(valueId, out var phiLocal))
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, phiLocal));
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
            throw new InvalidOperationException(
                $"SSA value %{valueId} ({value.Kind}) has no materialized location");
        }

        void EmitParallelCopies(IReadOnlyList<SsaTypedPhiCopy> copies)
        {
            // Load every old value before writing any destination. Reversed stores implement true
            // parallel-copy semantics even after later local coalescing introduces cycles.
            foreach (var copy in copies)
                EmitValue(copy.SourceValueId);
            for (int index = copies.Count - 1; index >= 0; index--)
                body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                    phiLocals[copies[index].PhiValueId]));
        }

        void EmitTerminator(BasicBlock block, int? nextBlockId)
        {
            var normal = ExecutableOutgoing(block.Id).ToArray();
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
                        block.Terminator, isLeave: false), Target(taken)));
                    if (!IsNext(fall))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(fall)));
                    break;
                case SemanticTerminatorKind.Switch:
                    var table = new ICilLabel[block.Terminator.TargetInstructionIndices.Count];
                    foreach (var edge in normal.Where(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchCase))
                        table[edge.SwitchCaseIndex!.Value] = Target(edge);
                    if (table.Any(label => label is null))
                        throw new InvalidOperationException($"B{block.Id} has incomplete switch");
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Switch, table.ToList()));
                    var defaultEdge = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchDefault);
                    if (!IsNext(defaultEdge))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br,
                            Target(defaultEdge)));
                    break;
                default:
                    body.Instructions.Add(new CilInstruction(SemanticCilLowerer.Lower(
                        block.Terminator, isLeave: false)));
                    break;
            }
        }

        IEnumerable<ControlFlowEdge> ExecutableOutgoing(int blockId) =>
            plan.DeadCode.Sccp.ExecutableEdges.Where(edge =>
                edge.SourceBlockId == blockId
                && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));
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
            throw new InvalidOperationException($"{variable} is not a local");
        return (variable.Temporary ? temps : locals)[variable.Index];
    }

    private static Parameter Argument(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self : target.Parameters[vmIndex - 1];
        return target.Parameters[vmIndex];
    }
}
