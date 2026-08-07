using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Emits a detached EH-aware SSA body. Source variables keep their original mutable slots, while
/// evaluation-stack phis, exception objects and operation results use exact typed locals. The real
/// target body is never replaced; unsupported EH shapes fail closed before production activation.
/// </summary>
internal static class EhSsaShadowEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!plan.Eligible)
            throw new InvalidOperationException($"EH SSA plan is not eligible: {plan.Reason}");
        if (!ReferenceEquals(plan.DeadCode.Sccp.Graph.Source, graph))
            throw new InvalidOperationException("EH SSA plan belongs to a different CFG");
        var verification = EhSsaShadowPlanVerifier.Verify(plan);
        if (!verification.Valid)
            throw new InvalidOperationException("invalid EH SSA plan: "
                + string.Join("; ", verification.Errors));
        if (decoded.ExceptionHandlers.Count == 0 || graph.ExceptionRegions.Count == 0)
            throw new InvalidOperationException("EH SSA shadow emission requires EH");
        if (plan.EdgeCopies.Any(copy => copy.Placement == SsaEdgeCopyPlacement.MethodEntry))
            throw new InvalidOperationException("evaluation-stack copies at method entry are invalid");

        var installed = target.CilMethodBody;
        var owner = new MethodDefinition(target.Name, target.Attributes,
            target.Signature ?? throw new InvalidOperationException("target has no signature"),
            verify: false);
        var body = new CilMethodBody { InitializeLocals = true };
        owner.CilMethodBody = body;
        try
        {
            EmitBody(module, target, decoded, graph, plan, tempLocalTypes, body);
            if (!ReferenceEquals(target.CilMethodBody, installed))
                throw new InvalidOperationException("EH SSA shadow emitter changed the target body");
            return body;
        }
        finally
        {
            owner.CilMethodBody = null;
            if (!ReferenceEquals(target.CilMethodBody, installed))
                throw new InvalidOperationException("EH SSA shadow emitter changed the target body");
        }
    }

    private static void EmitBody(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        CilMethodBody body)
    {
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);
        var stackPhis = plan.StackPhiTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var exceptions = plan.ExceptionObjectTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var spills = plan.OperationSpillTypes.ToDictionary(pair => pair.Key,
            pair => Declare(body, importer, pair.Value));
        var labels = plan.BlockOrder.ToDictionary(id => id, _ => new CilInstructionLabel());
        var starts = new Dictionary<int, int>();
        var ssa = plan.DeadCode.Sccp.Graph;
        var entries = plan.Entries.Entries.Where(entry =>
                plan.BlockOrder.Contains(entry.BlockId) && entry.ExceptionObject is not null)
            .GroupBy(entry => entry.BlockId)
            .ToDictionary(group => group.Key, group => group.Single());
        var pendingPrefixes = new List<CilInstruction>();

        for (int position = 0; position < plan.BlockOrder.Count; position++)
        {
            int blockId = plan.BlockOrder[position];
            starts[blockId] = body.Instructions.Count;
            if (entries.TryGetValue(blockId, out var entry))
            {
                int valueId = entry.ExceptionObject!.SsaValueId
                    ?? throw new InvalidOperationException($"EH entry B{blockId} has no SSA object");
                body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc, exceptions[valueId]));
            }
            foreach (var copy in plan.EdgeCopies.Where(copy =>
                copy.Placement == SsaEdgeCopyPlacement.TargetEntry
                && copy.TargetBlockId == blockId))
                EmitParallelCopies(copy.Copies);

            var block = ssa.Blocks[blockId];
            foreach (var instruction in block.Instructions.Where(instruction =>
                plan.EmissionInstructionIds.Contains(instruction.Id)))
                EmitInstruction(instruction);
            if (pendingPrefixes.Count != 0)
                throw new InvalidOperationException($"B{blockId} ends with an unattached CIL prefix");

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

        if (body.Instructions.Count == 0)
            throw new InvalidOperationException("EH SSA shadow emitter produced an empty body");
        // EH end labels need a concrete instruction even when the protected region reaches the
        // lexical end of the method. A bare nop would make PEVerify see a possible fall-through.
        // This unreachable fail-closed sentinel is valid for every return type.
        var endAnchor = new CilInstruction(CilOpCodes.Ldnull);
        body.Instructions.Add(endAnchor);
        body.Instructions.Add(new CilInstruction(CilOpCodes.Throw));
        foreach (var pair in starts.OrderByDescending(pair => pair.Key))
            labels[pair.Key].Instruction = body.Instructions[
                Math.Min(pair.Value, body.Instructions.Count - 1)];
        foreach (var clause in decoded.ExceptionHandlers)
            body.ExceptionHandlers.Add(BuildHandler(module, clause));

        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        body.Instructions.CalculateOffsets();
        body.VerifyLabels(calculateOffsets: false);
        body.ComputeMaxStack();
        CilTypeSafetyValidator.Validate(body);

        void EmitInstruction(SsaInstruction instruction)
        {
            if (instruction.Outputs.Count == 1
                && plan.FunctionPointers.TryGetValue(instruction.Outputs[0],
                    out var functionPointer))
            {
                RequireNoPrefixes(instruction);
                if (functionPointer.DefinitionInstructionId != instruction.Id)
                    throw new InvalidOperationException(
                        $"function pointer %{functionPointer.ValueId} has the wrong definition");
                return;
            }
            var effect = SsaStackSemantics.ForOperation(instruction.Operation);
            switch (effect.Behavior)
            {
                case SsaOperationBehavior.NoEffect:
                    if (instruction.Operation.Code == SemanticOperationCode.Prefix)
                        pendingPrefixes.Add(Lower(instruction.Operation));
                    return;
                case SsaOperationBehavior.LoadVariable:
                case SsaOperationBehavior.Duplicate:
                case SsaOperationBehavior.Pop:
                    return;
                case SsaOperationBehavior.StoreVariable:
                    RequireNoPrefixes(instruction);
                    foreach (int input in instruction.Inputs)
                        EmitValue(input, instruction.Id);
                    body.Instructions.Add(Lower(instruction.Operation));
                    return;
                case SsaOperationBehavior.General:
                    foreach (int input in instruction.Inputs)
                        EmitValue(input, instruction.Id);
                    foreach (var prefix in pendingPrefixes)
                        body.Instructions.Add(prefix);
                    pendingPrefixes.Clear();
                    body.Instructions.Add(Lower(instruction.Operation));
                    if (instruction.Outputs.Count == 1)
                    {
                        int output = instruction.Outputs[0];
                        body.Instructions.Add(spills.TryGetValue(output, out var outputSpill)
                            ? new CilInstruction(CilOpCodes.Stloc, outputSpill)
                            : new CilInstruction(CilOpCodes.Pop));
                    }
                    else if (instruction.Outputs.Count > 1)
                    {
                        throw new InvalidOperationException(
                            $"I{instruction.Id} has {instruction.Outputs.Count} outputs");
                    }
                    return;
                default:
                    throw new InvalidOperationException(
                        $"unsupported SSA behavior {effect.Behavior}");
            }
        }

        void RequireNoPrefixes(SsaInstruction instruction)
        {
            if (pendingPrefixes.Count != 0)
                throw new InvalidOperationException(
                    $"prefix before non-general I{instruction.Id} {instruction.Operation.Code}");
        }

        CilInstruction Lower(SemanticOperation operation) =>
            SemanticCfgEmitter.LowerOperation(module, importer, target, locals, temps, operation);

        void EmitValue(int valueId, int? consumerInstructionId = null)
        {
            if (plan.ConstantValues.TryGetValue(valueId, out object? constant))
            {
                body.Instructions.Add(SsaConstantEmitter.Emit(constant));
                return;
            }
            if (plan.VariablePhiSlots.TryGetValue(valueId, out var variable))
            {
                EmitVariableLoad(variable);
                return;
            }
            if (stackPhis.TryGetValue(valueId, out var stackPhi))
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, stackPhi));
                return;
            }
            if (exceptions.TryGetValue(valueId, out var exception))
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, exception));
                return;
            }
            if (plan.FunctionPointers.TryGetValue(valueId, out var functionPointer))
            {
                if (consumerInstructionId != functionPointer.ConsumerInstructionId)
                    throw new InvalidOperationException(
                        $"function pointer %{valueId} reached an unverified consumer");
                body.Instructions.Add(Lower(functionPointer.Operation));
                return;
            }
            if (spills.TryGetValue(valueId, out var spill))
            {
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, spill));
                return;
            }
            var value = ssa.Value(valueId);
            if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal)
            {
                EmitVariableLoad(value.Variable
                    ?? throw new InvalidOperationException($"%{valueId} has no variable"));
                return;
            }
            throw new InvalidOperationException(
                $"SSA value %{valueId} ({value.Kind}) has no materialized location");
        }

        void EmitVariableLoad(SsaVariableSlot variable)
        {
            body.Instructions.Add(variable.Kind == SsaVariableKind.Argument
                ? new CilInstruction(CilOpCodes.Ldarg, Argument(target, variable.Index))
                : new CilInstruction(CilOpCodes.Ldloc, Slot(variable, locals, temps)));
        }

        void EmitParallelCopies(IReadOnlyList<SsaTypedPhiCopy> copies)
        {
            foreach (var copy in copies)
                EmitValue(copy.SourceValueId);
            for (int index = copies.Count - 1; index >= 0; index--)
                body.Instructions.Add(new CilInstruction(CilOpCodes.Stloc,
                    stackPhis[copies[index].PhiValueId]));
        }

        void EmitTerminator(BasicBlock block, int? nextBlockId)
        {
            var normal = plan.DeadCode.Sccp.ExecutableEdges.Where(edge =>
                edge.SourceBlockId == block.Id
                && !ControlFlowEdgeSemantics.IsException(edge.Kind)).ToArray();
            bool IsNext(ControlFlowEdge edge) => edge.TargetBlockId == nextBlockId;
            CilInstructionLabel Target(ControlFlowEdge edge) => labels[edge.TargetBlockId];

            switch (block.Terminator.Kind)
            {
                case SemanticTerminatorKind.FallThrough:
                case SemanticTerminatorKind.Branch:
                    var successor = normal.SingleOrDefault()
                        ?? throw new InvalidOperationException($"B{block.Id} has no unique successor");
                    if (successor.Kind == ControlFlowEdgeKind.Leave)
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Leave, Target(successor)));
                    else if (!IsNext(successor))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(successor)));
                    return;
                case SemanticTerminatorKind.Conditional:
                    var taken = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.ConditionalTaken);
                    var fall = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.ConditionalFallThrough);
                    RejectNonLocalBranch(block, taken);
                    RejectNonLocalBranch(block, fall);
                    body.Instructions.Add(new CilInstruction(SemanticCilLowerer.Lower(
                        block.Terminator, isLeave: false), Target(taken)));
                    if (!IsNext(fall))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(fall)));
                    return;
                case SemanticTerminatorKind.Switch:
                    var table = new ICilLabel[block.Terminator.TargetInstructionIndices.Count];
                    foreach (var edge in normal.Where(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchCase))
                    {
                        RejectNonLocalBranch(block, edge);
                        table[edge.SwitchCaseIndex!.Value] = Target(edge);
                    }
                    if (table.Any(label => label is null))
                        throw new InvalidOperationException($"B{block.Id} has incomplete switch");
                    body.Instructions.Add(new CilInstruction(CilOpCodes.Switch, table.ToList()));
                    var defaultEdge = normal.Single(edge =>
                        edge.Kind == ControlFlowEdgeKind.SwitchDefault);
                    RejectNonLocalBranch(block, defaultEdge);
                    if (!IsNext(defaultEdge))
                        body.Instructions.Add(new CilInstruction(CilOpCodes.Br, Target(defaultEdge)));
                    return;
                default:
                    body.Instructions.Add(new CilInstruction(SemanticCilLowerer.Lower(
                        block.Terminator, isLeave: false)));
                    return;
            }
        }

        void RejectNonLocalBranch(BasicBlock source, ControlFlowEdge edge)
        {
            if (edge.Kind == ControlFlowEdgeKind.Leave
                || source.RegionPath.ExitsTo(graph.Blocks[edge.TargetBlockId].RegionPath))
                throw new InvalidOperationException(
                    $"B{source.Id} requires conditional/switch leave lowering");
        }

        CilExceptionHandler BuildHandler(ModuleDefinition sourceModule, EhClause clause)
        {
            var handler = new CilExceptionHandler
            {
                HandlerType = (CilExceptionHandlerType)clause.ClauseType,
                TryStart = Boundary(clause.TryStart),
                TryEnd = Boundary(clause.TryEnd + 1),
                HandlerStart = Boundary(clause.HandlerStart),
                HandlerEnd = Boundary(clause.HandlerEnd + 1),
            };
            if (clause.ClauseType == 0)
            {
                if (!clause.HasExtraToken
                    || !sourceModule.TryLookupMember(
                        new MetadataToken((uint)clause.ExtraToken), out var member)
                    || member is not ITypeDefOrRef catchType)
                    throw new InvalidOperationException("catch clause has no resolvable type");
                handler.ExceptionType = importer.ImportType(catchType);
            }
            else if (clause.ClauseType == 1)
            {
                if (!clause.HasExtraToken)
                    throw new InvalidOperationException("filter clause has no filter start");
                handler.FilterStart = Boundary(clause.ExtraToken);
            }
            return handler;
        }

        CilInstructionLabel Boundary(int vmIndex)
        {
            var block = plan.BlockOrder.Select(id => graph.Blocks[id])
                .FirstOrDefault(candidate => candidate.StartInstructionIndex >= vmIndex);
            if (block is not null)
                return labels[block.Id];
            return new CilInstructionLabel(endAnchor);
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
