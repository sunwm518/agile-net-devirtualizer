using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Adapts a proven raw value-type final argument to a reference-typed call parameter. Restricting
/// this pass to the immediate top-of-stack argument makes insertion unambiguous; buried arguments
/// still require explicit reordering and remain validator-rejected until that broader work exists.
/// </summary>
internal static class CilCallArgumentAdapter
{
    /// <summary>
    /// Restores the CLR protected-access shape when VM coercion inserted a base-type cast on
    /// <c>this</c>. A protected member is legal through the current derived instance, but retyping
    /// that same receiver as the base declaring type makes the call unverifiable. The cast is
    /// removed only when both inheritance and the exact implicit-this producer are proven.
    /// </summary>
    public static void RestoreProtectedThisReceivers(CilMethodBody body, MethodDefinition owner)
    {
        if (owner.Parameters.ThisParameter is not { } thisParameter)
            return;

        var instructions = body.Instructions;
        for (int callIndex = 0; callIndex < instructions.Count; callIndex++)
        {
            if (instructions[callIndex].OpCode.Code is not (CilCode.Call or CilCode.Callvirt)
                || instructions[callIndex].Operand is not IMethodDescriptor called)
                continue;

            if (Resolve(called, owner) is not { } definition)
                continue;

            if (!IsProtected(definition))
                continue;

            bool ownerCanUse = OwnerCanUseProtectedMember(owner, definition);
            bool foundReceiver = CilTypeSafetyValidator.TryGetReceiverProducerIndex(
                instructions, callIndex, called, out int receiverIndex, out var receiver);
            bool castMatches = foundReceiver
                && receiver.OpCode.Code == CilCode.Castclass
                && receiver.Operand is ITypeDefOrRef castType
                && castType.Resolve(owner.DeclaringType?.DeclaringModule?.RuntimeContext) == definition.DeclaringType;
            bool receiverIsThis = foundReceiver && receiverIndex > 0
                && LoadsThis(instructions[receiverIndex - 1], thisParameter);

            if (Environment.GetEnvironmentVariable("DBG_PROTECTED") == "1")
                Console.Error.WriteLine($"[protected-receiver] owner=0x{owner.MetadataToken.ToInt32():X8} " +
                    $"call={definition.FullName} inherit={ownerCanUse} " +
                    $"receiver={(foundReceiver ? receiver.OpCode.Code.ToString() : "none")} " +
                    $"cast={castMatches} this={receiverIsThis}");

            if (!ownerCanUse || !castMatches || !receiverIsThis)
                continue;

            instructions.RemoveAt(receiverIndex);
            callIndex--;
        }
    }

    private static MethodDefinition? Resolve(IMethodDescriptor method, MethodDefinition owner)
    {
        try { return method.Resolve(owner.DeclaringType?.DeclaringModule?.RuntimeContext); }
        catch { return null; }
    }

    private static bool IsProtected(MethodDefinition method) => method.IsFamily || method.IsFamilyOrAssembly;

    private static bool OwnerCanUseProtectedMember(MethodDefinition owner, MethodDefinition called)
    {
        if (owner.DeclaringType is not { } ownerType || called.DeclaringType is not { } declaringType)
            return false;
        try
        {
            var context = owner.DeclaringType?.DeclaringModule?.RuntimeContext;
            for (TypeDefinition? current = ownerType; current is not null;
                 current = current.BaseType?.Resolve(context))
            {
                if (ReferenceEquals(current, declaringType)
                    || current.FullName == declaringType.FullName
                        && current.DeclaringModule?.Assembly?.Name == declaringType.DeclaringModule?.Assembly?.Name)
                    return true;
            }
            return false;
        }
        catch { return false; }
    }

    private static bool LoadsThis(CilInstruction instruction, Parameter thisParameter) =>
        instruction.OpCode.Code == CilCode.Ldarg_0
        || instruction.OpCode.Code is CilCode.Ldarg or CilCode.Ldarg_S
            && ReferenceEquals(instruction.Operand, thisParameter);

    public static void BoxValueTypeLastArguments(CilMethodBody body)
    {
        var instructions = body.Instructions;
        for (int i = 0; i < instructions.Count; i++)
        {
            if (instructions[i].OpCode.Code is not (CilCode.Call or CilCode.Callvirt or CilCode.Newobj)
                || instructions[i].Operand is not IMethodDescriptor target
                || !CilTypeSafetyValidator.TryGetBoxableLastArgument(instructions, i, target, out var valueType))
                continue;

            instructions.Insert(i, new CilInstruction(CilOpCodes.Box, valueType));
            i++; // skip the call, shifted one slot to the right by the inserted box.
        }
    }

    /// <summary>
    /// Adds the CLR prefix required when a virtual receiver is a managed pointer to a concrete value
    /// type (or generic parameter). Receiver discovery uses the same full argument-expression walk
    /// as the conservative validator, so argument-bearing calls are handled without guessing from a
    /// linear symbolic stack.
    /// </summary>
    public static void ConstrainManagedPointerReceivers(CilMethodBody body)
    {
        var instructions = body.Instructions;
        for (int i = 0; i < instructions.Count; i++)
        {
            if (instructions[i].OpCode.Code != CilCode.Callvirt
                || instructions[i].Operand is not IMethodDescriptor target
                || i > 0 && instructions[i - 1].OpCode.Code == CilCode.Constrained
                || !CilTypeSafetyValidator.TryGetConstrainedReceiverType(
                    instructions, i, target, out var receiverType))
                continue;

            instructions.Insert(i, new CilInstruction(CilOpCodes.Constrained, receiverType));
            i++; // skip the call, shifted right by the inserted prefix.
        }
    }
}
