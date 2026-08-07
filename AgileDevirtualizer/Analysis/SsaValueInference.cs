using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal static class SsaValueInference
{
    public static AbstractValue ForOperation(
        SemanticOperation operation,
        IReadOnlyList<AbstractValue> inputs) => operation.Code switch
    {
        SemanticOperationCode.LoadConstant => AbstractValue.ConstantValue(operation.Operand),
        SemanticOperationCode.LoadNull => AbstractValue.Null,
        SemanticOperationCode.LoadString => AbstractValue.Reference("System.String", nonNull: true),
        SemanticOperationCode.LoadToken => AbstractValue.ValueType("System.RuntimeHandle"),
        SemanticOperationCode.LoadFunctionPointer => AbstractValue.NativeInt,
        SemanticOperationCode.LoadArgumentAddress or SemanticOperationCode.LoadLocalAddress =>
            AbstractValue.ManagedPointer(null),
        SemanticOperationCode.LoadField or SemanticOperationCode.LoadStaticField =>
            FieldValue(operation.Operand),
        SemanticOperationCode.LoadElement => Primitive(operation.Semantics.PrimitiveType),
        SemanticOperationCode.LoadElementAddress => AbstractValue.ManagedPointer(TypeName(operation.Operand)),
        SemanticOperationCode.LoadObject => ValueForType(operation.Operand),
        SemanticOperationCode.LoadArrayLength => AbstractValue.NativeInt,
        SemanticOperationCode.NewArray => AbstractValue.Reference(
            TypeName(operation.Operand) is { } type ? type + "[]" : null, nonNull: true),
        SemanticOperationCode.CompareEqual or SemanticOperationCode.CompareLessThan
            or SemanticOperationCode.CompareGreaterThan => AbstractValue.Int32,
        SemanticOperationCode.Convert => Primitive(operation.Semantics.PrimitiveType),
        SemanticOperationCode.Add or SemanticOperationCode.Subtract
            or SemanticOperationCode.Multiply or SemanticOperationCode.Divide
            or SemanticOperationCode.Remainder or SemanticOperationCode.BitwiseAnd
            or SemanticOperationCode.BitwiseOr or SemanticOperationCode.BitwiseXor =>
            Binary(inputs),
        SemanticOperationCode.ShiftLeft or SemanticOperationCode.ShiftRight
            or SemanticOperationCode.Negate or SemanticOperationCode.BitwiseNot =>
            inputs.FirstOrDefault(AbstractValue.Unknown) with { HasConstant = false, Constant = null },
        SemanticOperationCode.Box => AbstractValue.Reference(TypeName(operation.Operand), nonNull: true),
        SemanticOperationCode.UnboxAddress => AbstractValue.ManagedPointer(TypeName(operation.Operand)),
        SemanticOperationCode.UnboxValue => ValueForType(operation.Operand),
        SemanticOperationCode.Cast => AbstractValue.Reference(TypeName(operation.Operand)),
        SemanticOperationCode.IsInstance => AbstractValue.Reference(TypeName(operation.Operand)),
        SemanticOperationCode.Call or SemanticOperationCode.CallVirtual => CallValue(operation.Operand),
        SemanticOperationCode.NewObject => NewObjectValue(operation.Operand),
        _ => AbstractValue.Unknown,
    };

    public static AbstractValue ForInitialVariable(SsaVariableSlot slot) =>
        slot.Kind == SsaVariableKind.Argument ? AbstractValue.Unknown : AbstractValue.Unknown;

    private static AbstractValue Binary(IReadOnlyList<AbstractValue> inputs)
    {
        if (inputs.Count != 2 || inputs[0].Kind != inputs[1].Kind)
            return AbstractValue.Unknown;
        return inputs[0] with { HasConstant = false, Constant = null };
    }

    private static AbstractValue FieldValue(object? operand)
    {
        if (operand is not IFieldDescriptor field || field.Signature?.FieldType is not { } type)
            return AbstractValue.Unknown;
        try
        {
            type = type.InstantiateGenericTypes(GenericContext.FromType(field.DeclaringType!));
        }
        catch
        {
            // Keep the declared field type when generic substitution cannot be resolved.
        }
        return ValueForType(type);
    }

    private static AbstractValue CallValue(object? operand)
    {
        if (operand is GetTypeFromHandleMarker)
            return AbstractValue.Reference("System.Type", nonNull: true);
        if (operand is not IMethodDescriptor method || method.Signature is not { } signature)
            return AbstractValue.Unknown;
        try
        {
            return ValueForType(signature.ReturnType.InstantiateGenericTypes(
                GenericContext.FromMethod(method)));
        }
        catch
        {
            return ValueForType(signature.ReturnType);
        }
    }

    private static AbstractValue NewObjectValue(object? operand)
    {
        if (operand is StringFromCharsCtorMarker)
            return AbstractValue.Reference("System.String", nonNull: true);
        if (operand is not IMethodDescriptor method)
            return AbstractValue.Unknown;
        var value = ValueForType(method.DeclaringType);
        return value.Kind == AbstractValueKind.Reference
            ? AbstractValue.Reference(value.ExactType, nonNull: true)
            : value;
    }

    private static AbstractValue Primitive(SemanticPrimitiveType type) => type switch
    {
        SemanticPrimitiveType.Int8 or SemanticPrimitiveType.UInt8
            or SemanticPrimitiveType.Int16 or SemanticPrimitiveType.UInt16
            or SemanticPrimitiveType.Int32 or SemanticPrimitiveType.UInt32 => AbstractValue.Int32,
        SemanticPrimitiveType.Int64 or SemanticPrimitiveType.UInt64 => AbstractValue.Int64,
        SemanticPrimitiveType.NativeInt or SemanticPrimitiveType.NativeUInt => AbstractValue.NativeInt,
        SemanticPrimitiveType.Float32 => AbstractValue.Float32,
        SemanticPrimitiveType.Float64 => AbstractValue.Float64,
        SemanticPrimitiveType.Reference => AbstractValue.Reference("System.Object"),
        SemanticPrimitiveType.Typed => AbstractValue.Unknown,
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
}
