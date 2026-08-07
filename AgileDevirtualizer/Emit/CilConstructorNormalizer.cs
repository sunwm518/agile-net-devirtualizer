using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Restores the verifier-required base-constructor prologue when a VM constructor performed
/// instance-field initialization before reflectively invoking its parameterless base constructor.
/// Only a straight-line, handler-free body and an exact implicit-this receiver are rewritten.
/// </summary>
internal static class CilConstructorNormalizer
{
    public static void MoveParameterlessBaseCallBeforeThisUse(CilMethodBody body, MethodDefinition owner)
    {
        if (!owner.IsConstructor || owner.IsStatic || body.ExceptionHandlers.Count != 0
            || owner.DeclaringType?.BaseType is not { } baseType
            || owner.Parameters.ThisParameter is not { } thisParameter)
            return;

        var instructions = body.Instructions;
        for (int callIndex = 0; callIndex < instructions.Count; callIndex++)
        {
            if (instructions[callIndex].OpCode.Code != CilCode.Call
                || instructions[callIndex].Operand is not IMethodDescriptor called
                || called.Name?.ToString() != ".ctor"
                || called.Signature is not { HasThis: true, ParameterTypes.Count: 0 }
                || !SameType(called.DeclaringType, baseType, owner.DeclaringType.DeclaringModule?.RuntimeContext)
                || HasControlFlowBefore(instructions, callIndex))
                continue;

            int receiverIndex = callIndex - 1;
            int castIndex = -1;
            if (receiverIndex >= 1
                && instructions[receiverIndex].OpCode.Code == CilCode.Castclass
                && instructions[receiverIndex].Operand is ITypeDefOrRef castType
                && SameType(castType, baseType, owner.DeclaringType.DeclaringModule?.RuntimeContext))
            {
                castIndex = receiverIndex;
                receiverIndex--;
            }

            if (receiverIndex < 0 || !LoadsThis(instructions[receiverIndex], thisParameter))
                continue;

            var loadThis = instructions[receiverIndex];
            var baseCall = instructions[callIndex];
            instructions.RemoveAt(callIndex);
            if (castIndex >= 0)
                instructions.RemoveAt(castIndex);
            instructions.RemoveAt(receiverIndex);
            instructions.Insert(0, baseCall);
            instructions.Insert(0, loadThis);
            return;
        }
    }

    private static bool HasControlFlowBefore(CilInstructionCollection instructions, int end)
    {
        for (int i = 0; i < end; i++)
            if (instructions[i].OpCode.FlowControl is CilFlowControl.Branch
                or CilFlowControl.ConditionalBranch or CilFlowControl.Return or CilFlowControl.Throw)
                return true;
        return false;
    }

    private static bool LoadsThis(CilInstruction instruction, Parameter thisParameter) =>
        instruction.OpCode.Code == CilCode.Ldarg_0
        || instruction.OpCode.Code is CilCode.Ldarg or CilCode.Ldarg_S
            && ReferenceEquals(instruction.Operand, thisParameter);

    private static bool SameType(ITypeDescriptor? left, ITypeDescriptor? right, RuntimeContext? context)
    {
        if (left is null || right is null)
            return false;
        if (ReferenceEquals(left, right) || left.FullName == right.FullName)
            return true;
        try
        {
            var l = left is ITypeDefOrRef lr ? lr.Resolve(context) : null;
            var r = right is ITypeDefOrRef rr ? rr.Resolve(context) : null;
            if (l is not null && r is not null)
                return ReferenceEquals(l, r) || l.FullName == r.FullName
                    && l.DeclaringModule?.Assembly?.Name == r.DeclaringModule?.Assembly?.Name;
            return left.FullName == right.FullName;
        }
        catch { return false; }
    }
}
