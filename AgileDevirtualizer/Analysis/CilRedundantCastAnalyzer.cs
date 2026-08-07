using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AgileDevirtualizer.Emit;

namespace AgileDevirtualizer.Analysis;

internal enum CilConversionDisposition
{
    ProvenRedundant,
    RepresentationChanging,
    RuntimeChecked,
    Unknown,
}

internal sealed record CilConversionClassification(
    int InstructionIndex,
    CilCode Code,
    string SourceType,
    string TargetType,
    CilConversionDisposition Disposition,
    bool Removable,
    string Reason);

internal sealed record CilRedundantCastAnalysis(
    IReadOnlyList<CilConversionClassification> Conversions)
{
    public int CastClass => Conversions.Count(item => item.Code == CilCode.Castclass);
    public int Box => Conversions.Count(item => item.Code == CilCode.Box);
    public int UnboxAny => Conversions.Count(item => item.Code == CilCode.Unbox_Any);
    public int Numeric => Conversions.Count(item => item.Code.ToString()
        .StartsWith("Conv_", StringComparison.Ordinal));
    public int Removable => Conversions.Count(item => item.Removable);
}

/// <summary>
/// Classifies conversion operations using only local CIL stack provenance and metadata types. The
/// analysis starts every basic block conservatively and therefore misses uncertain opportunities
/// instead of allowing a checked conversion to disappear.
/// </summary>
internal static class CilRedundantCastAnalyzer
{
    public static CilRedundantCastAnalysis Analyze(MethodDefinition target, CilMethodBody body)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(body);
        var result = new List<CilConversionClassification>();
        var starts = BlockStarts(body);
        var handlerEntries = HandlerEntries(target, body);
        for (int block = 0; block < starts.Length; block++)
        {
            int start = starts[block];
            int end = block + 1 < starts.Length ? starts[block + 1] : body.Instructions.Count;
            var stack = new List<StaticValue>();
            if (handlerEntries.TryGetValue(start, out var entry))
                stack.Add(entry);
            for (int index = start; index < end; index++)
                Simulate(target, body, index, stack, result);
        }
        return new CilRedundantCastAnalysis(result);
    }

    private static void Simulate(MethodDefinition target, CilMethodBody body, int index,
        List<StaticValue> stack, List<CilConversionClassification> result)
    {
        var instruction = body.Instructions[index];
        if (instruction.OpCode.Code == CilCode.Dup)
        {
            stack.Add(stack.Count == 0 ? StaticValue.Unknown : stack[^1]);
            return;
        }

        if (!TryStackCounts(target, instruction, out int pop, out int push))
        {
            stack.Clear();
            return;
        }
        while (stack.Count < pop)
            stack.Insert(0, StaticValue.Unknown);
        var popped = new List<StaticValue>(pop);
        for (int count = 0; count < pop; count++)
        {
            popped.Add(stack[^1]);
            stack.RemoveAt(stack.Count - 1);
        }

        if (IsAuditedConversion(instruction.OpCode.Code))
            result.Add(Classify(body, index, instruction, popped.FirstOrDefault()));
        for (int count = 0; count < push; count++)
            stack.Add(PushedValue(Module(target), target, body, instruction, popped));
    }

    private static CilConversionClassification Classify(CilMethodBody body, int index,
        CilInstruction instruction, StaticValue source)
    {
        string sourceName = source.Type?.FullName ?? source.Kind.ToString();
        string targetName = TargetName(instruction);
        bool protectedInstruction = CilLocalCleanup.IsProtected(body, index, index);
        if (instruction.OpCode.Code == CilCode.Castclass
            && instruction.Operand is ITypeDescriptor descriptor
            && TypeOf(descriptor, forceReference: true) is { } castTarget)
        {
            bool proven = source.Kind == StaticValueKind.Null
                || source.Kind is StaticValueKind.Reference or StaticValueKind.BoxedValue
                && source.Type is { } sourceType
                && IsAssignable(sourceType, castTarget, source.Kind == StaticValueKind.BoxedValue);
            if (proven)
            {
                return new CilConversionClassification(index, instruction.OpCode.Code,
                    sourceName, targetName, CilConversionDisposition.ProvenRedundant,
                    !protectedInstruction, protectedInstruction
                        ? "assignability is proven, but the cast is a branch/EH boundary"
                        : "source is null or statically assignable to the cast target");
            }
            return new CilConversionClassification(index, instruction.OpCode.Code,
                sourceName, targetName,
                source.Kind == StaticValueKind.Unknown
                    ? CilConversionDisposition.Unknown
                    : CilConversionDisposition.RuntimeChecked,
                false, "removing castclass could suppress InvalidCastException");
        }

        if (instruction.OpCode.Code == CilCode.Box)
            return Required(CilConversionDisposition.RepresentationChanging,
                "box changes a value into an object reference and may allocate");
        if (instruction.OpCode.Code == CilCode.Unbox_Any)
            return Required(CilConversionDisposition.RuntimeChecked,
                "unbox.any performs null/type checks and changes stack representation");
        if (TryIdentityNumeric(instruction.OpCode.Code, source, out string identityReason))
        {
            return new CilConversionClassification(index, instruction.OpCode.Code,
                sourceName, targetName, CilConversionDisposition.ProvenRedundant,
                !protectedInstruction, protectedInstruction
                    ? identityReason + ", but the conversion is a branch/EH boundary"
                    : identityReason);
        }
        return Required(instruction.OpCode.Code.ToString().Contains("Ovf",
                StringComparison.Ordinal)
                ? CilConversionDisposition.RuntimeChecked
                : CilConversionDisposition.RepresentationChanging,
            "numeric conversion may change width, signedness or floating-point precision");

        CilConversionClassification Required(CilConversionDisposition disposition,
            string reason) => new(index, instruction.OpCode.Code, sourceName, targetName,
                disposition, false, reason);
    }

    private static bool TryIdentityNumeric(CilCode code, StaticValue source,
        out string reason)
    {
        string? expected = code switch
        {
            CilCode.Conv_I4 => "System.Int32",
            CilCode.Conv_I8 => "System.Int64",
            CilCode.Conv_I => "System.IntPtr",
            CilCode.Conv_U => "System.UIntPtr",
            _ => null,
        };
        bool identity = expected is not null && source.Kind == StaticValueKind.Value
            && source.Type?.FullName == expected;
        reason = identity ? $"{code} preserves an already exact {expected} value" : string.Empty;
        return identity;
    }

    private static StaticValue PushedValue(ModuleDefinition module, MethodDefinition target,
        CilMethodBody body, CilInstruction instruction, IReadOnlyList<StaticValue> popped)
    {
        var code = instruction.OpCode.Code;
        if (code == CilCode.Ldnull) return StaticValue.Null;
        if (code == CilCode.Ldstr) return Reference(module.CorLibTypeFactory.String);
        if (TryLocal(body, instruction, out var localType)) return Value(localType);
        if (TryArgument(instruction, target, out var argumentType)) return Value(argumentType);
        if (code is CilCode.Ldfld or CilCode.Ldsfld
            && instruction.Operand is IFieldDescriptor field)
            return Value(InstantiateField(field));
        if (code is CilCode.Call or CilCode.Callvirt
            && instruction.Operand is IMethodDescriptor method)
            return Value(InstantiateReturn(method));
        if (code == CilCode.Newobj && instruction.Operand is IMethodDescriptor constructor)
            return Value(TypeOf(constructor.DeclaringType));
        if (code == CilCode.Newarr && instruction.Operand is ITypeDescriptor element
            && TypeOf(element) is { } elementType)
            return Reference(new SzArrayTypeSignature(elementType));
        if (code == CilCode.Box && instruction.Operand is ITypeDescriptor boxed)
            return new StaticValue(StaticValueKind.BoxedValue, TypeOf(boxed));
        if (code is CilCode.Castclass or CilCode.Isinst
            && instruction.Operand is ITypeDescriptor cast)
            return Reference(TypeOf(cast, forceReference: true));
        if (code == CilCode.Unbox_Any && instruction.Operand is ITypeDescriptor unboxed)
            return Value(TypeOf(unboxed));
        if (code is CilCode.Unbox or CilCode.Ldloca or CilCode.Ldloca_S
            or CilCode.Ldarga or CilCode.Ldarga_S or CilCode.Ldelema)
            return new StaticValue(StaticValueKind.ManagedPointer);
        if (code is CilCode.Ldobj or CilCode.Ldelem
            && instruction.Operand is ITypeDescriptor loaded)
            return Value(TypeOf(loaded));
        if (IsInt32(code)) return Value(module.CorLibTypeFactory.Int32);
        if (code == CilCode.Ldc_I8) return Value(module.CorLibTypeFactory.Int64);
        if (code == CilCode.Ldc_R4) return Value(module.CorLibTypeFactory.Single);
        if (code == CilCode.Ldc_R8) return Value(module.CorLibTypeFactory.Double);
        if (code == CilCode.Ldlen) return Value(module.CorLibTypeFactory.UIntPtr);
        if (code is CilCode.Ceq or CilCode.Cgt or CilCode.Cgt_Un
            or CilCode.Clt or CilCode.Clt_Un)
            return Value(module.CorLibTypeFactory.Int32);
        if (code.ToString().StartsWith("Conv_", StringComparison.Ordinal))
            return NumericResult(module, code);
        if (code is CilCode.Add or CilCode.Sub or CilCode.Mul or CilCode.Div or CilCode.Div_Un
            or CilCode.Rem or CilCode.Rem_Un or CilCode.And or CilCode.Or or CilCode.Xor
            or CilCode.Shl or CilCode.Shr or CilCode.Shr_Un or CilCode.Neg or CilCode.Not)
            return popped.Count > 0 ? popped[^1] : StaticValue.Unknown;
        if (code is CilCode.Ldelem_Ref or CilCode.Ldind_Ref)
            return new StaticValue(StaticValueKind.Reference);
        return StaticValue.Unknown;
    }

    private static bool TryLocal(CilMethodBody body, CilInstruction instruction,
        out TypeSignature? type)
    {
        type = instruction.Operand is CilLocalVariable local ? local.VariableType
            : ImplicitLocalIndex(instruction.OpCode.Code) is int index
                && index < body.LocalVariables.Count
                ? body.LocalVariables[index].VariableType : null;
        return instruction.OpCode.Code is CilCode.Ldloc or CilCode.Ldloc_S
            or CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3
            && type is not null;
    }

    private static bool TryArgument(CilInstruction instruction, MethodDefinition target,
        out TypeSignature? type)
    {
        type = instruction.Operand is Parameter parameter ? parameter.ParameterType : null;
        if (type is null && ImplicitArgumentIndex(instruction.OpCode.Code) is int index)
        {
            type = target.Parameters.ThisParameter is { } self
                ? index == 0 ? self.ParameterType : target.Parameters.ElementAtOrDefault(index - 1)?.ParameterType
                : target.Parameters.ElementAtOrDefault(index)?.ParameterType;
        }
        return instruction.OpCode.Code is CilCode.Ldarg or CilCode.Ldarg_S
            or CilCode.Ldarg_0 or CilCode.Ldarg_1 or CilCode.Ldarg_2 or CilCode.Ldarg_3
            && type is not null;
    }

    private static int? ImplicitLocalIndex(CilCode code) => code switch
    {
        CilCode.Ldloc_0 => 0, CilCode.Ldloc_1 => 1,
        CilCode.Ldloc_2 => 2, CilCode.Ldloc_3 => 3, _ => null,
    };

    private static int? ImplicitArgumentIndex(CilCode code) => code switch
    {
        CilCode.Ldarg_0 => 0, CilCode.Ldarg_1 => 1,
        CilCode.Ldarg_2 => 2, CilCode.Ldarg_3 => 3, _ => null,
    };

    private static TypeSignature? InstantiateField(IFieldDescriptor field)
    {
        var type = field.Signature?.FieldType;
        try { return type?.InstantiateGenericTypes(GenericContext.FromType(field.DeclaringType!)); }
        catch { return type; }
    }

    private static TypeSignature? InstantiateReturn(IMethodDescriptor method)
    {
        var type = method.Signature?.ReturnType;
        if (type?.IsTypeOf("System", "Void") == true) return null;
        try { return type?.InstantiateGenericTypes(GenericContext.FromMethod(method)); }
        catch { return type; }
    }

    private static bool IsAssignable(TypeSignature source, TypeSignature target, bool boxed)
    {
        if (SameType(source, target)) return true;
        if (target.IsTypeOf("System", "Object")) return true;
        if (boxed && target.IsTypeOf("System", "ValueType")) return true;
        if (source is SzArrayTypeSignature or ArrayTypeSignature
            && target.IsTypeOf("System", "Array")) return true;
        if (IsAssignableThroughHierarchy(source, target)) return true;
        return false;
    }

    /// <summary>
    /// Resolves the real CLR base-type and interface hierarchy via AsmResolver's own
    /// <c>IsAssignableTo</c> — the exact same proof <see cref="CilTypeSafetyValidator"/> already
    /// trusts to verify emitted bodies. A safe upcast (e.g. a field declared <c>Label</c> passed
    /// where <c>Control</c> is expected) can never throw regardless of which base type or interface
    /// in the chain the cast names, so this covers that generically instead of only exact identity.
    /// Any resolution failure (an assembly outside the search path, an unresolvable type spec) fails
    /// closed: the cast is kept, never guessed away.
    /// </summary>
    private static bool IsAssignableThroughHierarchy(TypeSignature source, TypeSignature target)
    {
        try
        {
            var context = source.ContextModule?.RuntimeContext ?? target.ContextModule?.RuntimeContext;
            return source.IsAssignableTo(target, context);
        }
        catch { return false; }
    }

    // SignatureComparer compares the encoded signature and its resolution scope without resolving
    // the type. This keeps shadow analysis observational while preventing equal namespace/name
    // pairs from different assemblies from being treated as the same runtime type.
    private static bool SameType(TypeSignature left, TypeSignature right) =>
        SignatureComparer.Default.Equals(left, right);

    private static StaticValue Value(TypeSignature? type)
    {
        if (type is null) return StaticValue.Unknown;
        if (type is ByReferenceTypeSignature or PointerTypeSignature)
            return new StaticValue(StaticValueKind.ManagedPointer, type);
        try { return type.IsValueType
            ? new StaticValue(StaticValueKind.Value, type) : Reference(type); }
        catch { return StaticValue.Unknown; }
    }

    private static StaticValue Reference(TypeSignature? type) =>
        new(StaticValueKind.Reference, type);

    private static TypeSignature? TypeOf(ITypeDescriptor? descriptor,
        bool forceReference = false)
    {
        if (descriptor is null) return null;
        try
        {
            if (descriptor is TypeSignature signature)
                return forceReference && signature.IsValueType
                    ? signature.GetUnderlyingTypeDefOrRef()?.ToTypeSignature(false) : signature;
            if (descriptor is ITypeDefOrRef reference)
            {
                if (forceReference)
                    return reference.ToTypeSignature(false);
                return TryIsValueType(reference, out bool isValueType)
                    ? reference.ToTypeSignature(isValueType) : null;
            }
            return descriptor.ToTypeSignature(descriptor.ContextModule?.RuntimeContext);
        }
        catch { return null; }
    }

    private static bool TryIsValueType(ITypeDefOrRef type, out bool isValueType)
    {
        try
        {
            if (type is TypeDefinition definition)
            {
                isValueType = definition.IsValueType;
                return true;
            }
            if (type is TypeSpecification { Signature: { } signature })
            {
                isValueType = signature.IsValueType;
                return true;
            }
        }
        catch
        {
            // Unknown remains unknown; never guess class versus value type.
        }
        isValueType = false;
        return false;
    }

    private static StaticValue NumericResult(ModuleDefinition module, CilCode code) => code switch
    {
        CilCode.Conv_I4 or CilCode.Conv_Ovf_I4 or CilCode.Conv_Ovf_I4_Un => Value(module.CorLibTypeFactory.Int32),
        CilCode.Conv_I8 or CilCode.Conv_Ovf_I8 or CilCode.Conv_Ovf_I8_Un => Value(module.CorLibTypeFactory.Int64),
        CilCode.Conv_I or CilCode.Conv_Ovf_I or CilCode.Conv_Ovf_I_Un => Value(module.CorLibTypeFactory.IntPtr),
        CilCode.Conv_U or CilCode.Conv_Ovf_U or CilCode.Conv_Ovf_U_Un => Value(module.CorLibTypeFactory.UIntPtr),
        CilCode.Conv_R4 => Value(module.CorLibTypeFactory.Single),
        CilCode.Conv_R8 or CilCode.Conv_R_Un => Value(module.CorLibTypeFactory.Double),
        _ => StaticValue.Unknown,
    };

    private static string TargetName(CilInstruction instruction) =>
        instruction.Operand is ITypeDescriptor type ? type.FullName ?? "<type>"
        : instruction.OpCode.Code.ToString();

    private static bool IsAuditedConversion(CilCode code) => code is CilCode.Castclass
        or CilCode.Box or CilCode.Unbox_Any || code.ToString().StartsWith("Conv_",
            StringComparison.Ordinal);

    private static bool IsInt32(CilCode code) => code is CilCode.Ldc_I4_M1
        or CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2
        or CilCode.Ldc_I4_3 or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5
        or CilCode.Ldc_I4_6 or CilCode.Ldc_I4_7 or CilCode.Ldc_I4_8
        or CilCode.Ldc_I4 or CilCode.Ldc_I4_S;

    private static bool TryStackCounts(MethodDefinition target, CilInstruction instruction,
        out int pop, out int push)
    {
        if (instruction.OpCode.Code == CilCode.Ret)
        {
            pop = target.Signature?.ReturnType.IsTypeOf("System", "Void") == false ? 1 : 0;
            push = 0;
            return true;
        }
        if (instruction.OpCode.Code is CilCode.Call or CilCode.Callvirt or CilCode.Newobj
            && instruction.Operand is IMethodDescriptor method && method.Signature is { } signature)
        {
            bool construct = instruction.OpCode.Code == CilCode.Newobj;
            pop = signature.ParameterTypes.Count + (construct ? 0 : signature.HasThis ? 1 : 0);
            push = construct || !signature.ReturnType.IsTypeOf("System", "Void") ? 1 : 0;
            return true;
        }
        pop = Count(instruction.OpCode.StackBehaviourPop);
        push = Count(instruction.OpCode.StackBehaviourPush);
        return pop >= 0 && push >= 0;
    }

    private static int Count(CilStackBehaviour behaviour) => behaviour switch
    {
        CilStackBehaviour.Pop0 or CilStackBehaviour.Push0 => 0,
        CilStackBehaviour.VarPop or CilStackBehaviour.VarPush or CilStackBehaviour.PopAll => -1,
        _ => behaviour.ToString().Split('_').Length,
    };

    private static int[] BlockStarts(CilMethodBody body)
    {
        var byInstruction = body.Instructions.Select((instruction, index) => (instruction, index))
            .ToDictionary(pair => pair.instruction, pair => pair.index,
                ReferenceIdentityComparer<CilInstruction>.Instance);
        var starts = new SortedSet<int> { 0 };
        for (int index = 0; index < body.Instructions.Count; index++)
        {
            AddOperand(body.Instructions[index].Operand);
            if (index + 1 < body.Instructions.Count && body.Instructions[index].OpCode.FlowControl
                is CilFlowControl.Branch or CilFlowControl.ConditionalBranch
                    or CilFlowControl.Return or CilFlowControl.Throw)
                starts.Add(index + 1);
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            Add(handler.TryStart); Add(handler.TryEnd); Add(handler.HandlerStart);
            Add(handler.HandlerEnd); Add(handler.FilterStart);
        }
        return starts.Where(index => index >= 0 && index < body.Instructions.Count).ToArray();

        void AddOperand(object? operand)
        {
            if (operand is ICilLabel singleLabel) Add(singleLabel);
            if (operand is IList<ICilLabel> labels)
                foreach (var itemLabel in labels) Add(itemLabel);
        }
        void Add(ICilLabel? label)
        {
            if (label is CilInstructionLabel { Instruction: { } instruction }
                && byInstruction.TryGetValue(instruction, out int index)) starts.Add(index);
        }
    }

    private static Dictionary<int, StaticValue> HandlerEntries(MethodDefinition target,
        CilMethodBody body)
    {
        var index = body.Instructions.Select((instruction, position) => (instruction, position))
            .ToDictionary(pair => pair.instruction, pair => pair.position,
                ReferenceIdentityComparer<CilInstruction>.Instance);
        var result = new Dictionary<int, StaticValue>();
        foreach (var handler in body.ExceptionHandlers)
        {
            if (handler.HandlerType == CilExceptionHandlerType.Exception)
                Add(handler.HandlerStart, Reference(TypeOf(handler.ExceptionType,
                    forceReference: true) ?? Module(target).CorLibTypeFactory.Object));
            if (handler.FilterStart is not null)
                Add(handler.FilterStart, Reference(Module(target).CorLibTypeFactory.Object));
        }
        return result;
        void Add(ICilLabel? label, StaticValue value)
        {
            if (label is CilInstructionLabel { Instruction: { } instruction }
                && index.TryGetValue(instruction, out int position)) result[position] = value;
        }
    }

    private static ModuleDefinition Module(MethodDefinition target) =>
        target.DeclaringType?.DeclaringModule
        ?? throw new InvalidOperationException("method is not attached to a module");

    private enum StaticValueKind { Unknown, Null, Reference, BoxedValue, Value, ManagedPointer }

    private readonly record struct StaticValue(StaticValueKind Kind, TypeSignature? Type = null)
    {
        public static StaticValue Unknown => new(StaticValueKind.Unknown);
        public static StaticValue Null => new(StaticValueKind.Null);
    }
}
