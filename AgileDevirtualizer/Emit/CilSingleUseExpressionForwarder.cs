using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Keeps a single-use local value on the evaluation stack by deleting an adjacent
/// <c>stloc; ldloc</c> pair. No operation is reordered and no CIL/EH boundary is crossed.
/// </summary>
internal static class CilSingleUseExpressionForwarder
{
    public static CilExpressionForwardingResult Run(CilMethodBody body)
    {
        int pairs = 0;
        bool changed;
        do
        {
            changed = TryForwardOne(body);
            if (changed)
                pairs++;
        } while (changed);
        int locals = CilLocalCleanup.RemoveUnusedLocals(body);
        return new CilExpressionForwardingResult(pairs, pairs * 2, locals);
    }

    private static bool TryForwardOne(CilMethodBody body)
    {
        for (int index = 0; index + 1 < body.Instructions.Count; index++)
        {
            var store = body.Instructions[index];
            var load = body.Instructions[index + 1];
            if (!TryStoredLocal(store, out var local)
                || !TryLoadedLocal(load, out var loaded)
                || !ReferenceEquals(local, loaded))
                continue;
            var references = body.Instructions.Where(instruction =>
                ReferenceEquals(instruction.Operand, local)).ToArray();
            if (references.Length != 2 || !ReferenceEquals(references[0], store)
                || !ReferenceEquals(references[1], load))
                continue;
            if (CilLocalCleanup.IsProtected(body, index, index + 1)
                || !CilLocalCleanup.ShareBasicBlock(body, new[] { index, index + 1 }))
                continue;

            // Removing the pair leaves exactly the value consumed by stloc on the stack for the
            // former ldloc consumer. Since the instructions are adjacent, no effect moves.
            body.Instructions.RemoveAt(index + 1);
            body.Instructions.RemoveAt(index);
            return true;
        }
        return false;
    }

    private static bool TryLoadedLocal(CilInstruction instruction, out CilLocalVariable local)
    {
        local = instruction.Operand as CilLocalVariable ?? null!;
        return local is not null && instruction.OpCode.Code is CilCode.Ldloc or CilCode.Ldloc_S;
    }

    private static bool TryStoredLocal(CilInstruction instruction, out CilLocalVariable local)
    {
        local = instruction.Operand as CilLocalVariable ?? null!;
        return local is not null && instruction.OpCode.Code is CilCode.Stloc or CilCode.Stloc_S;
    }
}

internal sealed record CilExpressionForwardingResult(
    int ForwardedValues,
    int RemovedInstructions,
    int RemovedLocals);
