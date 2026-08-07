using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Rejects managed-pointer shapes that a height-only max-stack calculation accepts but the CLR
/// type verifier rejects. The checks are structural and conservative: an uncertain body stays VM
/// backed instead of being replaced by unverifiable CIL.
/// </summary>
internal static class CilTypeSafetyValidator
{
    internal static bool TryGetBoxableLastArgument(CilInstructionCollection instructions, int callIndex,
                                                   IMethodDescriptor target, out ITypeDefOrRef valueType)
    {
        valueType = null!;
        if (target.Signature is not { ParameterTypes.Count: > 0 } signature
            || !IsDefiniteReferenceType(signature.ParameterTypes[^1])
            || ContainsUnsubstitutedGenericParameter(signature.ParameterTypes[^1])
            || !TryFindSingleValueExpression(instructions, callIndex, out int start)
            || !TryInferExpressionResult(instructions, start, callIndex, out var actual)
            || actual is not { Kind: StackValueKind.Value, Type: { IsValueType: true } type })
            return false;

        valueType = type.ToTypeDefOrRef();
        return true;
    }

    internal static bool TryGetConstrainedReceiverType(CilInstructionCollection instructions, int callIndex,
                                                       IMethodDescriptor target, out ITypeDefOrRef receiverType)
    {
        receiverType = null!;
        if (!TryFindReceiverProducer(instructions, callIndex, target, out var receiver))
            return false;

        TypeSignature? pointedTo = receiver.OpCode.Code switch
        {
            CilCode.Ldarga or CilCode.Ldarga_S when receiver.Operand is Parameter parameter
                => parameter.ParameterType,
            CilCode.Ldloca or CilCode.Ldloca_S when receiver.Operand is CilLocalVariable local
                => local.VariableType,
            CilCode.Ldelema or CilCode.Unbox when receiver.Operand is ITypeDefOrRef type
                => TypeOf(type),
            _ => null,
        };
        if (pointedTo is null or ByReferenceTypeSignature)
            return false;

        bool constrainable;
        try { constrainable = pointedTo is GenericParameterSignature || pointedTo.IsValueType; }
        catch { return false; }
        if (!constrainable)
            return false;

        try { receiverType = pointedTo.ToTypeDefOrRef(); }
        catch { return false; }
        return true;
    }

    public static void Validate(CilMethodBody body)
    {
        var instructions = body.Instructions;
        for (int i = 0; i < instructions.Count; i++)
        {
            if (IsStoreLocal(instructions[i]) && i > 0 && IsManagedPointerProducer(instructions[i - 1])
                && instructions[i].Operand is CilLocalVariable local
                && local.VariableType is not ByReferenceTypeSignature)
            {
                throw new InvalidProgramException(
                    $"managed pointer stored in non-byref local at IL_{instructions[i].Offset:X4}");
            }

            if (instructions[i].OpCode.Code == CilCode.Callvirt
                && instructions[i].Operand is IMethodDescriptor target
                && !HasConstrainedPrefix(instructions, i)
                && TryFindReceiverProducer(instructions, i, target, out var receiver)
                && IsManagedPointerProducer(receiver))
            {
                throw new InvalidProgramException(
                    $"unconstrained callvirt on managed-pointer receiver at IL_{instructions[i].Offset:X4}");
            }

            if (instructions[i].OpCode.Code is CilCode.Call or CilCode.Callvirt or CilCode.Newobj
                && instructions[i].Operand is IMethodDescriptor called
                && HasInvalidCallArgument(instructions, i, called))
            {
                throw new InvalidProgramException(
                    $"argument type is incompatible with call signature at IL_{instructions[i].Offset:X4}");
            }
        }
    }

    private static bool HasInvalidCallArgument(CilInstructionCollection instructions, int callIndex,
                                               IMethodDescriptor target)
    {
        if (target.Signature is not { ParameterTypes.Count: > 0 } signature)
            return false;
        int end = callIndex;
        for (int parameterIndex = signature.ParameterTypes.Count - 1; parameterIndex >= 0; parameterIndex--)
        {
            if (!TryFindSingleValueExpression(instructions, end, out int start)
                || !TryInferExpressionResult(instructions, start, end, out var actual))
                return false;
            TypeSignature expected = signature.ParameterTypes[parameterIndex];
            if (IsDefinitelyIncompatible(actual, expected))
                return true;
            end = start;
        }
        return false;
    }

    private static bool IsDefinitelyIncompatible(InferredValue actual, TypeSignature expected)
    {
        if (!IsDefiniteReferenceType(expected) || ContainsUnsubstitutedGenericParameter(expected) || actual.IsNull)
            return false;
        if (actual.Kind == StackValueKind.Value)
            return true;
        if (actual.Kind != StackValueKind.Reference || actual.Type is null)
            return false;
        if (actual.Type.FullName == expected.FullName || expected.IsTypeOf("System", "Object"))
            return false;
        try
        {
            var context = actual.Type.ContextModule?.RuntimeContext ?? expected.ContextModule?.RuntimeContext;
            var actualDefinition = actual.Type.GetUnderlyingTypeDefOrRef()?.Resolve(context);
            var expectedDefinition = expected.GetUnderlyingTypeDefOrRef()?.Resolve(context);
            return actualDefinition is { IsSealed: true }
                && expectedDefinition is { IsInterface: false }
                && !actual.Type.IsAssignableTo(expected, context);
        }
        catch { return false; }
    }

    private static bool TryFindSingleValueExpression(CilInstructionCollection instructions, int end,
                                                     out int start)
    {
        for (start = end - 1; start >= 0; start--)
        {
            if (IsControlFlowBoundary(instructions[start]))
                break;
            if (TrySegmentNetStack(instructions, start, end, out int net) && net == 1)
                return true;
        }
        start = -1;
        return false;
    }

    private static bool TryInferExpressionResult(CilInstructionCollection instructions, int start, int end,
                                                 out InferredValue result)
    {
        var stack = new Stack<InferredValue>();
        for (int i = start; i < end; i++)
        {
            var instruction = instructions[i];
            if (instruction.OpCode.Code == CilCode.Dup)
            {
                if (stack.Count == 0) { result = default; return false; }
                stack.Push(stack.Peek());
                continue;
            }

            if (!TryStackCounts(instruction, out int pop, out int push) || stack.Count < pop)
            {
                result = default;
                return false;
            }
            for (int j = 0; j < pop; j++) stack.Pop();
            for (int j = 0; j < push; j++) stack.Push(PushedValue(instruction));
        }

        if (stack.Count == 1)
        {
            result = stack.Pop();
            return true;
        }
        result = default;
        return false;
    }

    private static bool TryStackCounts(CilInstruction instruction, out int pop, out int push)
    {
        pop = BehaviourCount(instruction.OpCode.StackBehaviourPop);
        push = BehaviourCount(instruction.OpCode.StackBehaviourPush);
        if (pop != VariableBehaviour && push != VariableBehaviour)
            return pop >= 0 && push >= 0;

        if (instruction.Operand is not IMethodDescriptor method || method.Signature is not { } signature)
            return false;
        bool newObject = instruction.OpCode.Code == CilCode.Newobj;
        pop = signature.ParameterTypes.Count + (newObject ? 0 : signature.HasThis ? 1 : 0);
        push = newObject || !signature.ReturnType.IsTypeOf("System", "Void") ? 1 : 0;
        return true;
    }

    private static InferredValue PushedValue(CilInstruction instruction)
    {
        var code = instruction.OpCode.Code;
        if (code == CilCode.Ldnull)
            return new InferredValue(StackValueKind.Reference, null, IsNull: true);
        if (code == CilCode.Ldstr)
            return new InferredValue(StackValueKind.Reference);
        if (code is CilCode.Box or CilCode.Castclass or CilCode.Isinst)
            return new InferredValue(StackValueKind.Reference,
                instruction.Operand is ITypeDefOrRef reference ? TypeOf(reference) : null);
        if (code is CilCode.Ldloca or CilCode.Ldloca_S or CilCode.Ldarga or CilCode.Ldarga_S
            or CilCode.Ldelema or CilCode.Unbox)
            return new InferredValue(StackValueKind.ManagedPointer);
        if (code is CilCode.Ldloc or CilCode.Ldloc_S && instruction.Operand is CilLocalVariable local)
            return ValueOf(local.VariableType);
        if (code is CilCode.Ldfld or CilCode.Ldsfld && instruction.Operand is IFieldDescriptor field)
            return ValueOf(field.Signature?.FieldType);
        if (code is CilCode.Call or CilCode.Callvirt && instruction.Operand is IMethodDescriptor method)
            return ValueOf(method.Signature?.ReturnType);
        if (code == CilCode.Newobj && instruction.Operand is IMethodDescriptor constructor
            && constructor.DeclaringType is { } constructed)
            return TryIsValueType(constructed, out bool constructedValueType)
                ? new InferredValue(constructedValueType ? StackValueKind.Value : StackValueKind.Reference,
                    TypeOf(constructed))
                : new InferredValue(StackValueKind.Unknown);
        if (code == CilCode.Unbox_Any && instruction.Operand is ITypeDefOrRef unboxed)
            return new InferredValue(IsValueType(unboxed) ? StackValueKind.Value : StackValueKind.Reference,
                TypeOf(unboxed));
        if (code is CilCode.Ldc_I4 or CilCode.Ldc_I4_S or CilCode.Ldc_I4_M1
            or CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2 or CilCode.Ldc_I4_3
            or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5 or CilCode.Ldc_I4_6 or CilCode.Ldc_I4_7
            or CilCode.Ldc_I4_8 or CilCode.Ldc_I8 or CilCode.Ldc_R4 or CilCode.Ldc_R8
            or CilCode.Ldtoken or CilCode.Ldelem_I or CilCode.Ldelem_I1 or CilCode.Ldelem_U1
            or CilCode.Ldelem_I2 or CilCode.Ldelem_U2 or CilCode.Ldelem_I4 or CilCode.Ldelem_U4
            or CilCode.Ldelem_I8 or CilCode.Ldelem_R4 or CilCode.Ldelem_R8)
            return new InferredValue(StackValueKind.Value);
        return new InferredValue(StackValueKind.Unknown);
    }

    private static InferredValue ValueOf(TypeSignature? type)
    {
        if (type is null or GenericParameterSignature) return new InferredValue(StackValueKind.Unknown);
        if (type is ByReferenceTypeSignature) return new InferredValue(StackValueKind.ManagedPointer, type);
        try { return new InferredValue(type.IsValueType ? StackValueKind.Value : StackValueKind.Reference, type); }
        catch { return new InferredValue(StackValueKind.Unknown); }
    }

    private static TypeSignature? TypeOf(ITypeDescriptor type)
    {
        try { return type.ToTypeSignature(type.ContextModule?.RuntimeContext); }
        catch { return null; }
    }

    private static bool TryIsValueType(ITypeDescriptor type, out bool isValueType)
    {
        try
        {
            if (type is TypeDefinition definition) isValueType = definition.IsValueType;
            else if (type is TypeSpecification specification) isValueType = specification.Signature?.IsValueType == true;
            else if (type is TypeSignature signature) isValueType = signature.IsValueType;
            else if (type is ITypeDefOrRef reference
                     && reference.Resolve(reference.ContextModule?.RuntimeContext) is { } resolved)
                isValueType = resolved.IsValueType;
            else { isValueType = false; return false; }
            return true;
        }
        catch { isValueType = false; return false; }
    }

    private static bool IsValueType(ITypeDefOrRef type)
    {
        if (type is TypeDefinition definition) return definition.IsValueType;
        if (type is TypeSpecification specification) return specification.Signature?.IsValueType == true;
        try { return type.Resolve(type.ContextModule?.RuntimeContext)?.IsValueType == true; }
        catch { return false; }
    }

    private enum StackValueKind
    {
        Unknown,
        Value,
        Reference,
        ManagedPointer,
    }

    private readonly record struct InferredValue(StackValueKind Kind, TypeSignature? Type = null,
                                                 bool IsNull = false);

    private static bool IsDefiniteReferenceType(TypeSignature type) =>
        !type.IsValueType
        && type is not GenericParameterSignature
        && type is not ByReferenceTypeSignature
        && type is not PointerTypeSignature
        && type is not FunctionPointerTypeSignature;

    private static bool ContainsUnsubstitutedGenericParameter(TypeSignature type) =>
        type is GenericParameterSignature || type.FullName?.Contains('!') == true;

    private static bool TryFindReceiverProducer(CilInstructionCollection instructions, int callIndex,
                                                IMethodDescriptor target, out CilInstruction receiver)
    {
        return TryGetReceiverProducerIndex(instructions, callIndex, target, out _, out receiver);
    }

    internal static bool TryGetReceiverProducerIndex(CilInstructionCollection instructions, int callIndex,
        IMethodDescriptor target, out int receiverIndex, out CilInstruction receiver)
    {
        receiverIndex = -1;
        receiver = null!;
        if (target.Signature is not { HasThis: true } signature)
            return false;

        int requiredArguments = signature.ParameterTypes.Count;
        if (requiredArguments == 0)
        {
            if (callIndex == 0 || IsControlFlowBoundary(instructions[callIndex - 1]))
                return false;
            receiverIndex = callIndex - 1;
            receiver = instructions[callIndex - 1];
            return true;
        }
        for (int start = callIndex - 1; start >= 0; start--)
        {
            if (IsControlFlowBoundary(instructions[start]))
                return false;

            if (!TrySegmentNetStack(instructions, start, callIndex, out int net)
                || net != requiredArguments || start == 0)
                continue;

            receiverIndex = start - 1;
            receiver = instructions[receiverIndex];
            return true;
        }
        return false;
    }

    private static bool TrySegmentNetStack(CilInstructionCollection instructions, int start, int end,
                                           out int net)
    {
        net = 0;
        for (int i = start; i < end; i++)
        {
            int delta = NetDelta(instructions[i]);
            if (delta == int.MinValue)
                return false;
            net += delta;
            if (net < 0)
                return false;
        }
        return true;
    }

    private static int NetDelta(CilInstruction instruction)
    {
        int pop = BehaviourCount(instruction.OpCode.StackBehaviourPop);
        int push = BehaviourCount(instruction.OpCode.StackBehaviourPush);
        if (pop != VariableBehaviour && push != VariableBehaviour)
            return pop < 0 || push < 0 ? int.MinValue : push - pop;

        if (instruction.Operand is not IMethodDescriptor method || method.Signature is not { } signature)
            return int.MinValue;
        bool newObject = instruction.OpCode.Code == CilCode.Newobj;
        int popped = signature.ParameterTypes.Count + (newObject ? 0 : signature.HasThis ? 1 : 0);
        int pushed = newObject || !signature.ReturnType.IsTypeOf("System", "Void") ? 1 : 0;
        return pushed - popped;
    }

    private const int VariableBehaviour = -1;

    private static int BehaviourCount(CilStackBehaviour behaviour) => behaviour switch
    {
        CilStackBehaviour.Pop0 or CilStackBehaviour.Push0 => 0,
        CilStackBehaviour.VarPop or CilStackBehaviour.VarPush => VariableBehaviour,
        CilStackBehaviour.PopAll => int.MinValue,
        _ => behaviour.ToString().Split('_').Length,
    };

    private static bool HasConstrainedPrefix(CilInstructionCollection instructions, int callIndex) =>
        callIndex > 0 && instructions[callIndex - 1].OpCode.Code == CilCode.Constrained;

    private static bool IsStoreLocal(CilInstruction instruction) => instruction.OpCode.Code is
        CilCode.Stloc or CilCode.Stloc_S or CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3;

    private static bool IsManagedPointerProducer(CilInstruction instruction) => instruction.OpCode.Code is
        CilCode.Ldarga or CilCode.Ldarga_S or CilCode.Ldloca or CilCode.Ldloca_S
        or CilCode.Ldelema or CilCode.Unbox;

    private static bool IsControlFlowBoundary(CilInstruction instruction) => instruction.OpCode.FlowControl is
        CilFlowControl.Branch or CilFlowControl.ConditionalBranch or CilFlowControl.Return or CilFlowControl.Throw;
}
