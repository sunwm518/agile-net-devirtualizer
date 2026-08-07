using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>Abstract stack/local effects for semantic IR. Pure and observation-only.</summary>
internal static class SemanticTransfer
{
    public static AbstractState Transfer(BasicBlock block, AbstractState entry)
    {
        if (!entry.Reachable)
            return entry;
        var state = new AbstractStateBuilder(entry.WithRegion(block.RegionPath));
        foreach (var operation in block.Operations)
            Apply(operation, state);
        ApplyTerminator(block.Terminator, state);
        return state.Snapshot();
    }

    private static void Apply(SemanticOperation operation, AbstractStateBuilder state)
    {
        switch (operation.Code)
        {
            case SemanticOperationCode.Nop:
            case SemanticOperationCode.Prefix:
                return;
            case SemanticOperationCode.LoadConstant:
                state.Push(AbstractValue.ConstantValue(operation.Operand));
                return;
            case SemanticOperationCode.LoadNull:
                state.Push(AbstractValue.Null);
                return;
            case SemanticOperationCode.LoadString:
                state.Push(AbstractValue.Reference("System.String", nonNull: true));
                return;
            case SemanticOperationCode.LoadToken:
                state.Push(AbstractValue.ValueType("System.RuntimeHandle"));
                return;
            case SemanticOperationCode.LoadFunctionPointer:
                state.Push(AbstractValue.NativeInt);
                return;
            case SemanticOperationCode.LoadArgument:
                state.Push(AbstractValue.Unknown);
                return;
            case SemanticOperationCode.LoadArgumentAddress:
                state.Push(AbstractValue.ManagedPointer(null));
                return;
            case SemanticOperationCode.StoreArgument:
                state.Pop();
                return;
            case SemanticOperationCode.LoadLocal:
                state.Push(operation.Operand is SemanticLocalReference load
                    ? state.LoadLocal(load)
                    : AbstractValue.Unknown);
                return;
            case SemanticOperationCode.LoadLocalAddress:
                state.Push(AbstractValue.ManagedPointer(operation.Operand is SemanticLocalReference address
                    ? state.LoadLocal(address).ExactType
                    : null));
                return;
            case SemanticOperationCode.StoreLocal:
                var stored = state.Pop();
                if (operation.Operand is SemanticLocalReference store)
                    state.StoreLocal(store, stored);
                else
                    state.MarkImprecise();
                return;
            case SemanticOperationCode.LoadField:
                state.Pop();
                state.Push(FieldValue(operation.Operand));
                return;
            case SemanticOperationCode.LoadStaticField:
                state.Push(FieldValue(operation.Operand));
                return;
            case SemanticOperationCode.StoreField:
                state.Pop();
                state.Pop();
                return;
            case SemanticOperationCode.StoreStaticField:
                state.Pop();
                return;
            case SemanticOperationCode.LoadElement:
                state.Pop();
                state.Pop();
                state.Push(ValueForType(operation.Operand));
                return;
            case SemanticOperationCode.LoadElementAddress:
                state.Pop();
                state.Pop();
                state.Push(AbstractValue.ManagedPointer(TypeName(operation.Operand)));
                return;
            case SemanticOperationCode.StoreElement:
                state.Pop();
                state.Pop();
                state.Pop();
                return;
            case SemanticOperationCode.LoadObject:
                state.Pop();
                state.Push(ValueForType(operation.Operand));
                return;
            case SemanticOperationCode.StoreObject:
                state.Pop();
                state.Pop();
                return;
            case SemanticOperationCode.LoadArrayLength:
                state.Pop();
                state.Push(AbstractValue.NativeInt);
                return;
            case SemanticOperationCode.NewArray:
                state.Pop();
                state.Push(AbstractValue.Reference(TypeName(operation.Operand) + "[]", nonNull: true));
                return;
            case SemanticOperationCode.Add:
            case SemanticOperationCode.Subtract:
            case SemanticOperationCode.Multiply:
            case SemanticOperationCode.Divide:
            case SemanticOperationCode.Remainder:
            case SemanticOperationCode.BitwiseAnd:
            case SemanticOperationCode.BitwiseOr:
            case SemanticOperationCode.BitwiseXor:
            case SemanticOperationCode.ShiftLeft:
            case SemanticOperationCode.ShiftRight:
                ApplyBinary(operation.Code, state);
                return;
            case SemanticOperationCode.Negate:
            case SemanticOperationCode.BitwiseNot:
                ApplyUnary(operation.Code, state);
                return;
            case SemanticOperationCode.CompareEqual:
            case SemanticOperationCode.CompareLessThan:
            case SemanticOperationCode.CompareGreaterThan:
                ApplyComparison(operation.Code, state);
                return;
            case SemanticOperationCode.Convert:
                state.Pop();
                state.Push(NumericValue(operation.Semantics.PrimitiveType));
                return;
            case SemanticOperationCode.Box:
                state.Pop();
                state.Push(AbstractValue.Reference(TypeName(operation.Operand), nonNull: true));
                return;
            case SemanticOperationCode.UnboxAddress:
                state.Pop();
                state.Push(AbstractValue.ManagedPointer(TypeName(operation.Operand)));
                return;
            case SemanticOperationCode.UnboxValue:
                state.Pop();
                state.Push(ValueForType(operation.Operand));
                return;
            case SemanticOperationCode.Cast:
                var castSource = state.Pop();
                state.Push(AbstractValue.Reference(TypeName(operation.Operand),
                    nonNull: castSource.Nullability == AbstractNullability.NonNull));
                return;
            case SemanticOperationCode.IsInstance:
                state.Pop();
                state.Push(AbstractValue.Reference(TypeName(operation.Operand)));
                return;
            case SemanticOperationCode.Call:
            case SemanticOperationCode.CallVirtual:
                ApplyCall(operation.Operand, state);
                return;
            case SemanticOperationCode.NewObject:
                ApplyNewObject(operation.Operand, state);
                return;
            case SemanticOperationCode.Duplicate:
                state.Push(state.Peek());
                return;
            case SemanticOperationCode.Pop:
                state.Pop();
                return;
            case SemanticOperationCode.InitializeObject:
                state.Pop();
                return;
            default:
                state.MarkImprecise();
                return;
        }
    }

    private static void ApplyTerminator(SemanticTerminator terminator, AbstractStateBuilder state)
    {
        switch (terminator.Kind)
        {
            case SemanticTerminatorKind.Return:
                // A valid non-void return consumes its value; a void return starts with an empty
                // stack. The observational graph does not otherwise need the method signature.
                state.PopIfPresent();
                break;
            case SemanticTerminatorKind.Conditional:
            case SemanticTerminatorKind.Switch:
            case SemanticTerminatorKind.Throw:
            case SemanticTerminatorKind.EndFilter:
                state.Pop();
                break;
        }
    }

    private static void ApplyCall(object? operand, AbstractStateBuilder state)
    {
        if (operand is GetTypeFromHandleMarker)
        {
            state.Pop();
            state.Push(AbstractValue.Reference("System.Type", nonNull: true));
            return;
        }
        if (operand is not IMethodDescriptor method || method.Signature is not { } signature)
        {
            state.MarkImprecise();
            return;
        }

        for (int index = 0; index < signature.ParameterTypes.Count; index++)
            state.Pop();
        if (signature.HasThis)
            state.Pop();
        var returnType = signature.ReturnType.InstantiateGenericTypes(
            GenericContext.FromMethod(method));
        if (!returnType.IsTypeOf("System", "Void"))
            state.Push(ValueForType(returnType));
    }

    private static void ApplyNewObject(object? operand, AbstractStateBuilder state)
    {
        if (operand is StringFromCharsCtorMarker)
        {
            state.Pop();
            state.Push(AbstractValue.Reference("System.String", nonNull: true));
            return;
        }
        if (operand is not IMethodDescriptor constructor || constructor.Signature is not { } signature)
        {
            state.MarkImprecise();
            state.Push(AbstractValue.Unknown);
            return;
        }
        for (int index = 0; index < signature.ParameterTypes.Count; index++)
            state.Pop();
        var value = ValueForType(constructor.DeclaringType);
        state.Push(value.Kind == AbstractValueKind.Reference
            ? AbstractValue.Reference(value.ExactType, nonNull: true)
            : value);
    }

    private static void ApplyBinary(SemanticOperationCode operation, AbstractStateBuilder state)
    {
        var right = state.Pop();
        var left = state.Pop();
        if (TryFoldBinary(operation, left, right, out var folded))
        {
            state.Push(folded);
            return;
        }
        state.Push(left.Kind == right.Kind && left.Kind != AbstractValueKind.Unknown
            ? left with { HasConstant = false, Constant = null }
            : AbstractValue.Unknown);
    }

    private static void ApplyUnary(SemanticOperationCode operation, AbstractStateBuilder state)
    {
        var value = state.Pop();
        if (value.HasConstant && TryInt64(value.Constant, out long number))
        {
            long result = operation == SemanticOperationCode.Negate ? -number : ~number;
            state.Push(IntegralConstant(value.Kind, result));
            return;
        }
        state.Push(value with { HasConstant = false, Constant = null });
    }

    private static void ApplyComparison(SemanticOperationCode operation, AbstractStateBuilder state)
    {
        var right = state.Pop();
        var left = state.Pop();
        bool? result = operation switch
        {
            SemanticOperationCode.CompareEqual when left.HasConstant && right.HasConstant =>
                Equals(left.Constant, right.Constant),
            SemanticOperationCode.CompareLessThan when TryInt64(left.Constant, out long a)
                && TryInt64(right.Constant, out long b) => a < b,
            SemanticOperationCode.CompareGreaterThan when TryInt64(left.Constant, out long a)
                && TryInt64(right.Constant, out long b) => a > b,
            _ => null,
        };
        state.Push(result is { } known ? AbstractValue.ConstantValue(known ? 1 : 0) : AbstractValue.Int32);
    }

    private static bool TryFoldBinary(
        SemanticOperationCode operation,
        AbstractValue left,
        AbstractValue right,
        out AbstractValue result)
    {
        result = AbstractValue.Unknown;
        if (!left.HasConstant || !right.HasConstant
            || !TryInt64(left.Constant, out long a) || !TryInt64(right.Constant, out long b))
            return false;
        try
        {
            long value = operation switch
            {
                SemanticOperationCode.Add => a + b,
                SemanticOperationCode.Subtract => a - b,
                SemanticOperationCode.Multiply => a * b,
                SemanticOperationCode.Divide when b != 0 => a / b,
                SemanticOperationCode.Remainder when b != 0 => a % b,
                SemanticOperationCode.BitwiseAnd => a & b,
                SemanticOperationCode.BitwiseOr => a | b,
                SemanticOperationCode.BitwiseXor => a ^ b,
                SemanticOperationCode.ShiftLeft => a << (int)b,
                SemanticOperationCode.ShiftRight => a >> (int)b,
                _ => throw new InvalidOperationException(),
            };
            var resultKind = operation is SemanticOperationCode.ShiftLeft
                or SemanticOperationCode.ShiftRight
                ? left.Kind
                : left.Kind == right.Kind ? left.Kind : AbstractValueKind.Unknown;
            if (resultKind == AbstractValueKind.Unknown)
                return false;
            result = IntegralConstant(resultKind, value);
            return result.Kind != AbstractValueKind.Unknown;
        }
        catch
        {
            return false;
        }
    }

    private static AbstractValue IntegralConstant(AbstractValueKind kind, long value) => kind switch
    {
        AbstractValueKind.Int32 => AbstractValue.ConstantValue(unchecked((int)value)),
        AbstractValueKind.Int64 => AbstractValue.ConstantValue(value),
        _ => AbstractValue.Unknown,
    };

    private static AbstractValue FieldValue(object? operand)
    {
        if (operand is not IFieldDescriptor field || field.Signature?.FieldType is not { } fieldType)
            return AbstractValue.Unknown;
        try
        {
            fieldType = fieldType.InstantiateGenericTypes(
                GenericContext.FromType(field.DeclaringType!));
        }
        catch
        {
            // A non-generic or unresolved declaring type needs no substitution; retain the declared
            // field type and let the finite lattice represent any remaining generic parameter.
        }
        return ValueForType(fieldType);
    }

    private static AbstractValue NumericValue(SemanticPrimitiveType kind) => kind switch
    {
        SemanticPrimitiveType.Int8 or SemanticPrimitiveType.UInt8
            or SemanticPrimitiveType.Int16 or SemanticPrimitiveType.UInt16
            or SemanticPrimitiveType.Int32 or SemanticPrimitiveType.UInt32 =>
            AbstractValue.Int32,
        SemanticPrimitiveType.Int64 or SemanticPrimitiveType.UInt64 => AbstractValue.Int64,
        SemanticPrimitiveType.NativeInt or SemanticPrimitiveType.NativeUInt => AbstractValue.NativeInt,
        SemanticPrimitiveType.Float32 => AbstractValue.Float32,
        SemanticPrimitiveType.Float64 => AbstractValue.Float64,
        _ => AbstractValue.Unknown,
    };

    private static AbstractValue ValueForType(object? descriptor)
    {
        string? name = TypeName(descriptor);
        if (name is null)
            return AbstractValue.Unknown;
        return name switch
        {
            "System.Boolean" or "System.Byte" or "System.SByte" or "System.Char"
                or "System.Int16" or "System.UInt16" or "System.Int32" or "System.UInt32" =>
                AbstractValue.Int32,
            "System.Int64" or "System.UInt64" => AbstractValue.Int64,
            "System.IntPtr" or "System.UIntPtr" => AbstractValue.NativeInt,
            "System.Single" => AbstractValue.Float32,
            "System.Double" => AbstractValue.Float64,
            _ when IsValueType(descriptor) => AbstractValue.ValueType(name),
            _ => AbstractValue.Reference(name),
        };
    }

    private static string? TypeName(object? descriptor) => descriptor switch
    {
        TypeSignature signature => signature.FullName,
        ITypeDescriptor type => type.FullName,
        _ => null,
    };

    private static bool IsValueType(object? descriptor)
    {
        try
        {
            return descriptor switch
            {
                TypeSignature signature => signature.IsValueType,
                ITypeDescriptor type => type.Resolve(null)?.IsValueType ?? false,
                _ => false,
            };
        }
        catch
        {
            return false;
        }
    }

    private static bool TryInt64(object? value, out long number)
    {
        if (value is bool boolean)
        {
            number = boolean ? 1 : 0;
            return true;
        }
        if (value is byte or sbyte or short or ushort or int or uint or long or char)
        {
            number = Convert.ToInt64(value);
            return true;
        }
        number = 0;
        return false;
    }
}
