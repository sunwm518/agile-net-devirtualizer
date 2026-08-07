using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Propagates actual metadata types through SSA. Unlike AbstractValue, this result is suitable for
/// declaring CIL spill locals: unresolved nulls and conflicting joins never masquerade as object.
/// </summary>
internal static class SsaCilTypeAnalyzer
{
    private const int MaximumIterations = 1_000;

    public static SsaCilTypeResult Analyze(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        SsaGraph graph)
    {
        var exceptionTypes = ExceptionEntryModelBuilder.Build(module, graph).Entries
            .Where(entry => entry.ExceptionObject?.SsaValueId is not null)
            .ToDictionary(entry => entry.ExceptionObject!.SsaValueId!.Value,
                entry => entry.ExceptionObject!.StaticType);
        var values = graph.Values.ToDictionary(value => value.Id,
            value => InitialType(target, decoded, tempLocalTypes, exceptionTypes, value));
        bool changed;
        int iterations = 0;
        do
        {
            changed = false;
            iterations++;
            foreach (var block in graph.Blocks.Where(block => block.Reachable))
            {
                foreach (var phi in block.Phis)
                {
                    var joined = SsaCilType.Undefined;
                    foreach (var input in phi.Inputs)
                        joined = SsaCilType.Join(joined, values[input.ValueId]);
                    changed |= Merge(values, phi.Result.Id, joined);
                }

                foreach (var instruction in block.Instructions)
                {
                    if (instruction.Outputs.Count == 0)
                        continue;
                    var inputTypes = instruction.Inputs.Select(id => values[id]).ToArray();
                    var inferred = Infer(module, target, decoded, tempLocalTypes,
                        instruction.Operation, inputTypes);
                    foreach (int output in instruction.Outputs)
                        changed |= Merge(values, output, inferred);
                }
            }
        } while (changed && iterations < MaximumIterations);

        return new SsaCilTypeResult(graph, values, !changed, iterations);
    }

    private static SsaCilType InitialType(
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        IReadOnlyDictionary<int, TypeSignature?> exceptionTypes,
        SsaValue value)
    {
        if (value.Kind == SsaValueKind.InitialArgument && value.Variable is { } argument)
            return Exact(ArgumentType(target, argument.Index));
        if (value.Kind == SsaValueKind.InitialLocal && value.Variable is { } local)
        {
            var types = local.Temporary ? tempLocalTypes : decoded.Locals;
            return local.Index >= 0 && local.Index < types.Count
                ? Exact(types[local.Index]) : SsaCilType.Conflict;
        }
        return value.Kind == SsaValueKind.ExceptionObject
            ? Exact(exceptionTypes.GetValueOrDefault(value.Id))
            : SsaCilType.Undefined;
    }

    private static SsaCilType Infer(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        SemanticOperation operation,
        IReadOnlyList<SsaCilType> inputs) => operation.Code switch
    {
        SemanticOperationCode.LoadConstant => Primitive(module, operation.Semantics.PrimitiveType),
        SemanticOperationCode.LoadNull => SsaCilType.Null,
        SemanticOperationCode.LoadString => Exact(module.CorLibTypeFactory.String),
        SemanticOperationCode.LoadToken => RuntimeHandle(module, operation.Operand),
        SemanticOperationCode.LoadFunctionPointer => Exact(module.CorLibTypeFactory.IntPtr),
        SemanticOperationCode.LoadArgumentAddress => ByReference(
            operation.Operand is SemanticArgumentReference argument
                ? ArgumentType(target, argument.Index) : null),
        SemanticOperationCode.LoadLocalAddress => ByReference(
            operation.Operand is SemanticLocalReference local
                ? LocalType(decoded, tempLocalTypes, local) : null),
        SemanticOperationCode.LoadField or SemanticOperationCode.LoadStaticField =>
            FieldType(operation.Operand),
        SemanticOperationCode.LoadElement => operation.Semantics.PrimitiveType
            == SemanticPrimitiveType.Typed
                ? DescriptorType(operation.Operand)
                : Primitive(module, operation.Semantics.PrimitiveType),
        SemanticOperationCode.LoadElementAddress =>
            ByReference(DescriptorType(operation.Operand).Type),
        SemanticOperationCode.LoadObject => DescriptorType(operation.Operand),
        SemanticOperationCode.LoadArrayLength => Exact(module.CorLibTypeFactory.UIntPtr),
        SemanticOperationCode.NewArray => ArrayType(operation.Operand),
        SemanticOperationCode.Add or SemanticOperationCode.Subtract
            or SemanticOperationCode.Multiply or SemanticOperationCode.Divide
            or SemanticOperationCode.Remainder or SemanticOperationCode.BitwiseAnd
            or SemanticOperationCode.BitwiseOr or SemanticOperationCode.BitwiseXor =>
            BinaryNumeric(module, inputs),
        SemanticOperationCode.ShiftLeft or SemanticOperationCode.ShiftRight
            or SemanticOperationCode.Negate or SemanticOperationCode.BitwiseNot =>
            inputs.Count > 0 ? StackNumeric(module, inputs[0]) : SsaCilType.Conflict,
        SemanticOperationCode.CompareEqual or SemanticOperationCode.CompareLessThan
            or SemanticOperationCode.CompareGreaterThan => Exact(module.CorLibTypeFactory.Int32),
        SemanticOperationCode.Convert => Primitive(module, operation.Semantics.PrimitiveType),
        SemanticOperationCode.Box => Exact(module.CorLibTypeFactory.Object),
        SemanticOperationCode.UnboxAddress => ByReference(DescriptorType(operation.Operand).Type),
        SemanticOperationCode.UnboxValue => DescriptorType(operation.Operand),
        SemanticOperationCode.Cast or SemanticOperationCode.IsInstance =>
            ReferenceDescriptorType(operation.Operand),
        SemanticOperationCode.Call or SemanticOperationCode.CallVirtual =>
            CallType(module, operation.Operand),
        SemanticOperationCode.NewObject => NewObjectType(module, operation.Operand),
        _ => SsaCilType.Conflict,
    };

    private static SsaCilType RuntimeHandle(ModuleDefinition module, object? operand)
    {
        string name = operand switch
        {
            MemberReference { Signature: FieldSignature } or IFieldDescriptor =>
                "RuntimeFieldHandle",
            MemberReference { Signature: MethodSignature } or IMethodDescriptor =>
                "RuntimeMethodHandle",
            ITypeDescriptor => "RuntimeTypeHandle",
            _ => "RuntimeTypeHandle",
        };
        return Exact(SystemType(module, name, isValueType: true));
    }

    private static SsaCilType FieldType(object? operand)
    {
        if (operand is not IFieldDescriptor field || field.Signature?.FieldType is not { } type)
            return SsaCilType.Conflict;
        try { type = type.InstantiateGenericTypes(GenericContext.FromType(field.DeclaringType!)); }
        catch { }
        return Exact(type);
    }

    private static SsaCilType CallType(ModuleDefinition module, object? operand)
    {
        if (operand is GetTypeFromHandleMarker)
            return Exact(SystemType(module, "Type", isValueType: false));
        if (operand is not IMethodDescriptor method || method.Signature is not { } signature)
            return SsaCilType.Conflict;
        var type = signature.ReturnType;
        if (type.IsTypeOf("System", "Void"))
            return SsaCilType.Conflict;
        try { type = type.InstantiateGenericTypes(GenericContext.FromMethod(method)); }
        catch { }
        return Exact(type);
    }

    private static SsaCilType NewObjectType(ModuleDefinition module, object? operand)
    {
        if (operand is StringFromCharsCtorMarker)
            return Exact(module.CorLibTypeFactory.String);
        return operand is IMethodDescriptor { DeclaringType: { } type }
            ? DescriptorType(type) : SsaCilType.Conflict;
    }

    private static SsaCilType ArrayType(object? operand)
    {
        var element = DescriptorType(operand);
        return element.Kind == SsaCilTypeKind.Exact
            ? Exact(new SzArrayTypeSignature(element.Type!)) : SsaCilType.Conflict;
    }

    private static SsaCilType ReferenceDescriptorType(object? operand)
    {
        if (operand is not ITypeDescriptor descriptor)
            return SsaCilType.Conflict;
        try
        {
            if (descriptor is TypeSignature signature)
                return Exact(signature.IsValueType
                    ? signature.GetUnderlyingTypeDefOrRef()!.ToTypeSignature(false) : signature);
            if (descriptor is ITypeDefOrRef reference)
                return Exact(reference.ToTypeSignature(false));
            return Exact(descriptor.ToTypeSignature(descriptor.ContextModule?.RuntimeContext));
        }
        catch { return SsaCilType.Conflict; }
    }

    private static SsaCilType DescriptorType(object? operand)
    {
        try
        {
            return operand switch
            {
                TypeSignature signature => Exact(signature),
                ITypeDefOrRef reference => Exact(reference.ToTypeSignature(IsValueType(reference))),
                ITypeDescriptor descriptor =>
                    Exact(descriptor.ToTypeSignature(descriptor.ContextModule?.RuntimeContext)),
                _ => SsaCilType.Conflict,
            };
        }
        catch { return SsaCilType.Conflict; }
    }

    private static SsaCilType BinaryNumeric(
        ModuleDefinition module,
        IReadOnlyList<SsaCilType> inputs)
    {
        if (inputs.Count != 2)
            return SsaCilType.Conflict;
        if (inputs.Any(input => input.Kind == SsaCilTypeKind.Undefined))
            return SsaCilType.Undefined;
        var left = StackNumeric(module, inputs[0]);
        var right = StackNumeric(module, inputs[1]);
        return left.Kind == SsaCilTypeKind.Exact
            && right.Kind == SsaCilTypeKind.Exact
            && left.Type!.FullName == right.Type!.FullName
            ? left : SsaCilType.Conflict;
    }

    private static SsaCilType StackNumeric(ModuleDefinition module, SsaCilType input)
    {
        if (input.Kind != SsaCilTypeKind.Exact || input.Type is null)
            return input.Kind == SsaCilTypeKind.Undefined
                ? SsaCilType.Undefined : SsaCilType.Conflict;
        return input.Type.FullName switch
        {
            "System.Boolean" or "System.Byte" or "System.SByte" or "System.Char"
                or "System.Int16" or "System.UInt16" or "System.Int32" or "System.UInt32" =>
                Exact(module.CorLibTypeFactory.Int32),
            "System.Int64" or "System.UInt64" => Exact(module.CorLibTypeFactory.Int64),
            "System.IntPtr" or "System.UIntPtr" => Exact(module.CorLibTypeFactory.IntPtr),
            "System.Single" => Exact(module.CorLibTypeFactory.Single),
            "System.Double" => Exact(module.CorLibTypeFactory.Double),
            _ => SsaCilType.Conflict,
        };
    }

    private static SsaCilType Primitive(
        ModuleDefinition module,
        SemanticPrimitiveType type) => type switch
    {
        SemanticPrimitiveType.Int8 => Exact(module.CorLibTypeFactory.SByte),
        SemanticPrimitiveType.UInt8 => Exact(module.CorLibTypeFactory.Byte),
        SemanticPrimitiveType.Int16 => Exact(module.CorLibTypeFactory.Int16),
        SemanticPrimitiveType.UInt16 => Exact(module.CorLibTypeFactory.UInt16),
        SemanticPrimitiveType.Int32 => Exact(module.CorLibTypeFactory.Int32),
        SemanticPrimitiveType.UInt32 => Exact(module.CorLibTypeFactory.UInt32),
        SemanticPrimitiveType.Int64 => Exact(module.CorLibTypeFactory.Int64),
        SemanticPrimitiveType.UInt64 => Exact(module.CorLibTypeFactory.UInt64),
        SemanticPrimitiveType.NativeInt => Exact(module.CorLibTypeFactory.IntPtr),
        SemanticPrimitiveType.NativeUInt => Exact(module.CorLibTypeFactory.UIntPtr),
        SemanticPrimitiveType.Float32 => Exact(module.CorLibTypeFactory.Single),
        SemanticPrimitiveType.Float64 => Exact(module.CorLibTypeFactory.Double),
        SemanticPrimitiveType.Reference => Exact(module.CorLibTypeFactory.Object),
        _ => SsaCilType.Conflict,
    };

    private static TypeSignature? LocalType(
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        SemanticLocalReference local)
    {
        var types = local.Temporary ? tempLocalTypes : decoded.Locals;
        return local.Index >= 0 && local.Index < types.Count ? types[local.Index] : null;
    }

    private static TypeSignature? ArgumentType(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self.ParameterType
                : vmIndex - 1 < target.Parameters.Count
                    ? target.Parameters[vmIndex - 1].ParameterType : null;
        return vmIndex >= 0 && vmIndex < target.Parameters.Count
            ? target.Parameters[vmIndex].ParameterType : null;
    }

    private static SsaCilType ByReference(TypeSignature? type) => type is null
        ? SsaCilType.Conflict : Exact(new ByReferenceTypeSignature(type));

    private static TypeSignature SystemType(
        ModuleDefinition module,
        string name,
        bool isValueType) => new TypeReference(module,
            module.CorLibTypeFactory.CorLibScope, "System", name)
        .ToTypeSignature(isValueType);

    private static SsaCilType Exact(TypeSignature? type) => type is null
        ? SsaCilType.Conflict : SsaCilType.Exact(type);

    private static bool Merge(
        IDictionary<int, SsaCilType> values,
        int valueId,
        SsaCilType incoming)
    {
        var joined = SsaCilType.Join(values[valueId], incoming);
        if (Same(values[valueId], joined))
            return false;
        values[valueId] = joined;
        return true;
    }

    private static bool Same(SsaCilType left, SsaCilType right) =>
        left.Kind == right.Kind && (left.Kind != SsaCilTypeKind.Exact
            || left.Type?.FullName == right.Type?.FullName
            && SafeIsValueType(left.Type!) == SafeIsValueType(right.Type!));

    private static bool SafeIsValueType(TypeSignature type)
    {
        try { return type.IsValueType; }
        catch { return false; }
    }

    private static bool IsValueType(ITypeDefOrRef type)
    {
        try
        {
            return type switch
            {
                TypeDefinition definition => definition.IsValueType,
                TypeSpecification specification => specification.Signature?.IsValueType == true,
                _ => type.Resolve(type.ContextModule?.RuntimeContext)?.IsValueType == true,
            };
        }
        catch { return false; }
    }
}
