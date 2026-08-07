using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>Conservative local-alias propagation and dead-local cleanup for detached CIL bodies.</summary>
internal static class CilLocalCleanup
{
    public static int Run(CilMethodBody body)
        => RunCore(body, requireSingleBasicBlock: false);

    /// <summary>
    /// EH-safe tier: aliases are propagated only when the definition and every use are in one CIL
    /// basic block. This prevents a linear local scan from crossing a handler boundary, branch
    /// target or alternate predecessor.
    /// </summary>
    public static int RunEhSafe(CilMethodBody body)
        => RunCore(body, requireSingleBasicBlock: true);

    private static int RunCore(CilMethodBody body, bool requireSingleBasicBlock)
    {
        int changes = 0;
        bool changed;
        do
        {
            changed = TryPropagateOneAlias(body, requireSingleBasicBlock);
            if (changed) changes++;
        } while (changed);
        if (!requireSingleBasicBlock)
        {
            changes += RemoveRedundantLocalCasts(body);
            changes += RemoveDeadIntPtrSizeCalls(body);
        }
        changes += RemoveUnusedLocals(body);
        return changes;
    }

    private static bool TryPropagateOneAlias(
        CilMethodBody body,
        bool requireSingleBasicBlock)
    {
        var instructions = body.Instructions;
        for (int index = 0; index + 1 < instructions.Count; index++)
        {
            if (!TryLoadedLocal(instructions[index], out var source))
                continue;
            int storeIndex = index + 1;
            if (instructions[storeIndex].OpCode.Code == CilCode.Castclass)
                storeIndex++;
            if (storeIndex >= instructions.Count
                || !TryStoredLocal(instructions[storeIndex], out var destination)
                || ReferenceEquals(source, destination))
                continue;
            bool exactType = source.VariableType.FullName
                == destination.VariableType.FullName;
            bool objectUpcast = requireSingleBasicBlock
                && destination.VariableType.IsTypeOf("System", "Object")
                && IsReferenceType(source.VariableType);
            if (!exactType && !objectUpcast)
                continue;
            if (storeIndex == index + 2)
            {
                if (instructions[index + 1].Operand is not ITypeDescriptor cast
                    || cast.FullName != destination.VariableType.FullName
                        && cast.FullName != source.VariableType.FullName)
                    continue;
            }

            var destinationReferences = instructions.Select((instruction, position) =>
                    (instruction, position))
                .Where(item => ReferenceEquals(item.instruction.Operand, destination)).ToArray();
            var stores = destinationReferences.Where(item => IsStore(item.instruction)).ToArray();
            var loads = destinationReferences.Where(item => IsLoad(item.instruction)).ToArray();
            if (stores.Length != 1 || stores[0].position != storeIndex || loads.Length == 0
                || destinationReferences.Length != stores.Length + loads.Length)
                continue;
            if (requireSingleBasicBlock)
            {
                if (objectUpcast)
                {
                    var sourceReferences = instructions.Select((instruction, position) =>
                            (instruction, position))
                        .Where(item => ReferenceEquals(item.instruction.Operand, source))
                        .ToArray();
                    if (sourceReferences.Count(item => IsStore(item.instruction)) != 1
                        || sourceReferences.Any(item => !IsStore(item.instruction)
                            && !IsLoad(item.instruction)))
                        continue;
                }
                else if (!ShareBasicBlock(body, new[] { index, storeIndex }
                    .Concat(loads.Select(load => load.position))))
                {
                    continue;
                }
            }
            int lastLoad = loads.Max(item => item.position);
            bool sourceReassigned = instructions.Select((instruction, position) =>
                    (instruction, position))
                .Any(item => item.position > storeIndex && item.position <= lastLoad
                    && ReferenceEquals(item.instruction.Operand, source)
                    && IsStore(item.instruction));
            if (sourceReassigned)
                continue;
            bool definitionInteriorProtected = storeIndex > index
                && IsProtected(body, index + 1, storeIndex);
            bool loadProtected = loads.Any(load => IsProtected(body,
                load.position, load.position));
            if (definitionInteriorProtected)
                continue;

            foreach (var load in loads.OrderByDescending(item => item.position))
            {
                var old = instructions[load.position];
                var replacement = new CilInstruction(CilOpCodes.Ldloc, source);
                instructions.RemoveAt(load.position);
                instructions.Insert(load.position, replacement);
                if (loadProtected)
                    Retarget(body, old, replacement);
                int castIndex = load.position + 1;
                if (objectUpcast && castIndex < instructions.Count
                    && instructions[castIndex].OpCode.Code == CilCode.Castclass
                    && instructions[castIndex].Operand is ITypeDescriptor loadCast
                    && loadCast.FullName == source.VariableType.FullName
                    && !IsProtected(body, castIndex, castIndex))
                    instructions.RemoveAt(castIndex);
            }
            if (storeIndex + 1 < instructions.Count)
                Retarget(body, instructions[index], instructions[storeIndex + 1]);
            for (int remove = storeIndex; remove >= index; remove--)
                instructions.RemoveAt(remove);
            return true;
        }
        return false;
    }

    private static bool IsReferenceType(TypeSignature type)
    {
        try
        {
            return !type.IsValueType && !type.FullName.EndsWith("&", StringComparison.Ordinal)
                && !type.FullName.EndsWith("*", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    internal static bool ShareBasicBlock(CilMethodBody body, IEnumerable<int> positions)
    {
        var selected = positions.Distinct().Order().ToArray();
        if (selected.Length == 0)
            return false;
        var indexByInstruction = new Dictionary<CilInstruction, int>();
        for (int index = 0; index < body.Instructions.Count; index++)
            indexByInstruction.TryAdd(body.Instructions[index], index);
        var boundaries = new SortedSet<int> { 0 };
        foreach (var instruction in body.Instructions.Select((value, index) =>
            (value, index)))
        {
            AddTarget(instruction.value.Operand);
            if (EndsBlock(instruction.value) && instruction.index + 1 < body.Instructions.Count)
                boundaries.Add(instruction.index + 1);
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            AddBoundary(handler.TryStart);
            AddBoundary(handler.TryEnd);
            AddBoundary(handler.HandlerStart);
            AddBoundary(handler.HandlerEnd);
            AddBoundary(handler.FilterStart);
        }

        int BlockStart(int position) => boundaries.Where(start => start <= position).Max();
        int expected = BlockStart(selected[0]);
        return selected.All(position => BlockStart(position) == expected);

        void AddTarget(object? operand)
        {
            if (operand is CilInstructionLabel { Instruction: { } target }
                && indexByInstruction.TryGetValue(target, out int targetIndex))
                boundaries.Add(targetIndex);
            if (operand is IList<ICilLabel> labels)
                foreach (var label in labels.OfType<CilInstructionLabel>())
                    if (label.Instruction is { } tableTarget
                        && indexByInstruction.TryGetValue(tableTarget, out int tableIndex))
                        boundaries.Add(tableIndex);
        }

        void AddBoundary(ICilLabel? label)
        {
            if (label is CilInstructionLabel { Instruction: { } instruction }
                && indexByInstruction.TryGetValue(instruction, out int index))
                boundaries.Add(index);
        }
    }

    private static bool EndsBlock(CilInstruction instruction) =>
        instruction.Operand is ICilLabel or IList<ICilLabel>
        || instruction.OpCode.Code is CilCode.Ret or CilCode.Throw or CilCode.Rethrow
            or CilCode.Endfinally or CilCode.Endfilter;

    private static int RemoveRedundantLocalCasts(CilMethodBody body)
    {
        int removed = 0;
        for (int index = body.Instructions.Count - 1; index >= 1; index--)
        {
            var cast = body.Instructions[index];
            if (cast.OpCode.Code != CilCode.Castclass
                || cast.Operand is not ITypeDescriptor target
                || !TryLoadedLocal(body.Instructions[index - 1], out var local)
                || local.VariableType.FullName != target.FullName
                || IsProtected(body, index, index))
                continue;
            body.Instructions.RemoveAt(index);
            removed++;
        }
        return removed;
    }

    private static int RemoveDeadIntPtrSizeCalls(CilMethodBody body)
    {
        int removed = 0;
        for (int index = body.Instructions.Count - 2; index >= 0; index--)
        {
            var instruction = body.Instructions[index];
            if (instruction.OpCode.Code != CilCode.Call
                || instruction.Operand is not IMethodDescriptor method
                || method.DeclaringType?.FullName != "System.IntPtr"
                || method.Name?.ToString() != "get_Size"
                || method.Signature is not { ParameterTypes.Count: 0 }
                || body.Instructions[index + 1].OpCode.Code != CilCode.Pop
                || IsProtected(body, index, index + 1))
                continue;
            body.Instructions.RemoveAt(index + 1);
            body.Instructions.RemoveAt(index);
            removed++;
        }
        return removed;
    }

    internal static int RemoveUnusedLocals(CilMethodBody body)
    {
        // Short local opcodes encode the collection index directly; do not renumber in that shape.
        if (body.Instructions.Any(instruction => instruction.OpCode.Code is
            CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3
            or CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3))
            return 0;
        int removed = 0;
        for (int index = body.LocalVariables.Count - 1; index >= 0; index--)
        {
            var local = body.LocalVariables[index];
            if (body.Instructions.Any(instruction => ReferenceEquals(instruction.Operand, local)))
                continue;
            body.LocalVariables.RemoveAt(index);
            removed++;
        }
        return removed;
    }

    internal static bool IsProtected(CilMethodBody body, int start, int end)
    {
        var range = body.Instructions.Skip(start).Take(end - start + 1).ToHashSet();
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is CilInstructionLabel { Instruction: { } target }
                && range.Contains(target))
                return true;
            if (instruction.Operand is IList<ICilLabel> labels
                && labels.Any(label => label is CilInstructionLabel { Instruction: { } target }
                    && range.Contains(target)))
                return true;
        }
        foreach (var handler in body.ExceptionHandlers)
            if (Boundary(handler.TryStart) || Boundary(handler.TryEnd)
                || Boundary(handler.HandlerStart) || Boundary(handler.HandlerEnd)
                || Boundary(handler.FilterStart))
                return true;
        return false;

        bool Boundary(ICilLabel? label) => label is CilInstructionLabel
            { Instruction: { } instruction } && range.Contains(instruction);
    }

    internal static void Retarget(
        CilMethodBody body,
        CilInstruction oldInstruction,
        CilInstruction newInstruction)
    {
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is CilInstructionLabel label
                && ReferenceEquals(label.Instruction, oldInstruction))
                label.Instruction = newInstruction;
            if (instruction.Operand is IList<ICilLabel> labels)
                foreach (var item in labels.OfType<CilInstructionLabel>().Where(label =>
                    ReferenceEquals(label.Instruction, oldInstruction)))
                    item.Instruction = newInstruction;
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            Move(handler.TryStart);
            Move(handler.TryEnd);
            Move(handler.HandlerStart);
            Move(handler.HandlerEnd);
            Move(handler.FilterStart);
        }

        void Move(ICilLabel? candidate)
        {
            if (candidate is CilInstructionLabel label
                && ReferenceEquals(label.Instruction, oldInstruction))
                label.Instruction = newInstruction;
        }
    }

    private static bool TryLoadedLocal(CilInstruction instruction, out CilLocalVariable local)
    {
        local = instruction.Operand as CilLocalVariable ?? null!;
        return local is not null && IsLoad(instruction);
    }

    private static bool TryStoredLocal(CilInstruction instruction, out CilLocalVariable local)
    {
        local = instruction.Operand as CilLocalVariable ?? null!;
        return local is not null && IsStore(instruction);
    }

    private static bool IsLoad(CilInstruction instruction) =>
        instruction.OpCode.Code is CilCode.Ldloc or CilCode.Ldloc_S;

    private static bool IsStore(CilInstruction instruction) =>
        instruction.OpCode.Code is CilCode.Stloc or CilCode.Stloc_S;
}
