using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Cross-block copy propagation for detached EH SSA bodies. The single-basic-block tier in
/// <see cref="CilLocalCleanup"/> already owns same-block copies; this tier only takes a copy whose
/// definition and every load span more than one block. It never guesses: the whole candidate is
/// rejected unless <see cref="CrossBlockPropagationLegality"/> proves every load stays inside the
/// exact same exception-region nesting and is unreachable from any intervening redefinition of the
/// source local.
/// </summary>
internal static class CilCrossBlockCopyPropagation
{
    public static int Run(CilMethodBody body)
    {
        int changes = 0;
        bool changed;
        do
        {
            changed = TryPropagateOneCopy(body);
            if (changed) changes++;
        } while (changed);
        changes += CilLocalCleanup.RemoveUnusedLocals(body);
        return changes;
    }

    private static bool TryPropagateOneCopy(CilMethodBody body)
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
                || ReferenceEquals(source, destination)
                || source.VariableType.FullName != destination.VariableType.FullName)
                continue;
            if (storeIndex == index + 2)
            {
                if (instructions[index + 1].Operand is not ITypeDescriptor cast
                    || cast.FullName != destination.VariableType.FullName)
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

            var positions = new[] { index, storeIndex }.Concat(loads.Select(load => load.position));
            if (CilLocalCleanup.ShareBasicBlock(body, positions))
                continue; // the single-basic-block tier already owns this shape

            if (!CrossBlockPropagationLegality.IsSafe(body, source, storeIndex,
                loads.Select(load => load.position)))
                continue;

            if (CilLocalCleanup.IsProtected(body, index + 1, storeIndex))
                continue;
            bool loadProtected = loads.Any(load => CilLocalCleanup.IsProtected(body,
                load.position, load.position));

            foreach (var load in loads.OrderByDescending(item => item.position))
            {
                var old = instructions[load.position];
                var replacement = new CilInstruction(CilOpCodes.Ldloc, source);
                instructions.RemoveAt(load.position);
                instructions.Insert(load.position, replacement);
                if (loadProtected)
                    CilLocalCleanup.Retarget(body, old, replacement);
            }
            if (storeIndex + 1 < instructions.Count)
                CilLocalCleanup.Retarget(body, instructions[index], instructions[storeIndex + 1]);
            for (int remove = storeIndex; remove >= index; remove--)
                instructions.RemoveAt(remove);
            return true;
        }
        return false;
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
