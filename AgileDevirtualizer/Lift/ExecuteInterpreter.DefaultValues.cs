using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>Recovers the VM's Activator-backed <c>default(T)</c> and by-ref assignment idiom.</summary>
internal sealed partial class ExecuteInterpreter
{
    private bool TryHandleDefaultValueCall(IMethodDescriptor method, MethodDefinition? definition)
    {
        if (definition is null || !ReferenceEquals(definition.DeclaringType, _vocab.ValueType)
            || definition.Signature is not { } signature)
            return false;

        if (IsDefaultValueFactory(definition, signature))
        {
            SymValue typeValue = Pop();
            if (!TryKnownTypeValue(typeValue, out TypeSignature type) || !type.IsValueType)
                throw new LiftUnsupported("default-value factory target type is not a known value type");
            _eval.Push(new SymValue.DefaultValue(type));
            return true;
        }

        if (!IsValueSetter(definition, signature) || _eval.Count < 2
            || _eval.ElementAt(0) is not SymValue.DefaultValue defaultValue
            || _eval.ElementAt(1) is not SymValue.OnStack { ManagedPointer: true })
            return false;

        Pop(); // default(T)
        Pop(); // the already-materialised managed pointer
        Emit(CilOpCodes.Initobj, defaultValue.Type.ToTypeDefOrRef());
        return true;
    }

    private bool IsDefaultValueFactory(MethodDefinition definition, MethodSignature signature)
    {
        if (!definition.IsStatic || signature.ParameterTypes.Count != 1
            || !signature.ParameterTypes[0].IsTypeOf("System", "Type")
            || ResolveTypeDef(signature.ReturnType) is not { } returned
            || !ReferenceEquals(returned, _vocab.ValueType)
            || definition.CilMethodBody is not { } body)
            return false;

        return body.Instructions.Any(instruction =>
            instruction.OpCode.Code is CilCode.Call or CilCode.Callvirt
            && instruction.Operand is IMethodDescriptor called
            && called.DeclaringType?.IsTypeOf("System", "Activator") == true
            && called.Name?.ToString() == "CreateInstance");
    }

    private bool IsValueSetter(MethodDefinition definition, MethodSignature signature)
    {
        if (definition.IsStatic || definition.Name?.ToString() == ".ctor"
            || signature.ParameterTypes.Count != 1
            || !signature.ParameterTypes[0].IsTypeOf("System", "Object")
            || !signature.ReturnType.IsTypeOf("System", "Void")
            || definition.CilMethodBody is not { } body
            || definition.DeclaringType is not { } owner)
            return false;

        return body.Instructions.Any(instruction => instruction.OpCode.Code == CilCode.Stfld
                                                    && instruction.Operand is IFieldDescriptor field
                                                    && IsFieldOnValueWrapper(field, owner));
    }

    private bool IsFieldOnValueWrapper(IFieldDescriptor field, TypeDefinition owner)
    {
        try
        {
            return ReferenceEquals(field.Resolve(_ctx)?.DeclaringType, owner);
        }
        catch
        {
            return false;
        }
    }
}
