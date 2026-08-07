using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Emits a probed VM comparison primitive as native CIL when the real evaluation-stack categories
/// are known. Logical enum distinctions disappear on the CLR stack, reference ordering is accepted
/// only against a proven null, and metadata-only trailing arguments are never materialised.
/// </summary>
internal sealed partial class ExecuteInterpreter
{
    private bool TryEmitNativeStackComparison(Relation relation, IReadOnlyList<SymValue> args)
    {
        int operands = relation == Relation.Falsy ? 1 : 2;
        if (args.Count < operands || args.Skip(operands).Any(IsStack))
            return false;

        var leftCategory = StackComparisonCategoryOf(args[0]);
        if (relation == Relation.Falsy)
            return EmitFalsy(args[0], leftCategory);

        var rightCategory = StackComparisonCategoryOf(args[1]);
        if (relation is Relation.Eq or Relation.Ne
            && AreEqualityCompatible(leftCategory, rightCategory))
        {
            EmitPush(args[0]);
            EmitPush(args[1]);
            Emit(CilOpCodes.Ceq);
            if (relation == Relation.Ne)
                EmitBooleanNot();
            return true;
        }

        if (TryEmitReferenceNullOrdering(relation, args[0], leftCategory, args[1], rightCategory))
            return true;
        if (!AreNumericCompatible(leftCategory, rightCategory)
            || relation is not (Relation.Lt or Relation.Gt or Relation.Le or Relation.Ge))
            return false;

        EmitPush(args[0]);
        EmitPush(args[1]);
        bool floating = leftCategory == StackComparisonCategory.Float;
        bool unorderedOrUnsigned = floating
            ? TryGetUnorderedBehavior(args, out bool unordered) && unordered
            : IsUnsigned(leftCategory) || IsUnsigned(rightCategory);
        EmitOrderedRelation(relation, floating, unorderedOrUnsigned);
        return true;
    }

    private bool EmitFalsy(SymValue value, StackComparisonCategory category)
    {
        if (category is StackComparisonCategory.Unknown)
            return false;

        EmitPush(value);
        switch (category)
        {
            case StackComparisonCategory.Reference:
            case StackComparisonCategory.Null:
                Emit(CilOpCodes.Ldnull);
                break;
            case StackComparisonCategory.I4Signed:
            case StackComparisonCategory.I4Unsigned:
                Emit(CilOpCodes.Ldc_I4_0);
                break;
            case StackComparisonCategory.I8Signed:
            case StackComparisonCategory.I8Unsigned:
                Emit(CilOpCodes.Ldc_I4_0);
                Emit(CilOpCodes.Conv_I8);
                break;
            case StackComparisonCategory.NativeSigned:
            case StackComparisonCategory.NativeUnsigned:
                Emit(CilOpCodes.Ldc_I4_0);
                Emit(CilOpCodes.Conv_I);
                break;
            case StackComparisonCategory.Float:
                Emit(CilOpCodes.Ldc_R8, 0d);
                break;
            default:
                return false;
        }
        Emit(CilOpCodes.Ceq);
        return true;
    }

    private bool TryEmitReferenceNullOrdering(Relation relation, SymValue left,
        StackComparisonCategory leftCategory, SymValue right, StackComparisonCategory rightCategory)
    {
        bool leftNull = leftCategory == StackComparisonCategory.Null;
        bool rightNull = rightCategory == StackComparisonCategory.Null;
        bool leftReference = leftCategory == StackComparisonCategory.Reference;
        bool rightReference = rightCategory == StackComparisonCategory.Reference;
        if (!(leftNull && rightReference || leftReference && rightNull)
            || relation is not (Relation.Lt or Relation.Gt))
            return false;

        EmitPush(left);
        EmitPush(right);
        bool canBeTrue = relation == Relation.Lt && leftNull || relation == Relation.Gt && rightNull;
        if (canBeTrue)
        {
            Emit(CilOpCodes.Ceq);
            EmitBooleanNot();
        }
        else
        {
            Emit(CilOpCodes.Pop);
            Emit(CilOpCodes.Pop);
            Emit(CilOpCodes.Ldc_I4_0);
        }
        return true;
    }

    private void EmitOrderedRelation(Relation relation, bool floating, bool unorderedOrUnsigned)
    {
        bool invert = relation is Relation.Le or Relation.Ge;
        bool useUn = unorderedOrUnsigned;
        CilOpCode operation;
        if (relation is Relation.Lt or Relation.Ge)
        {
            if (floating && invert) useUn = !useUn;
            operation = useUn ? CilOpCodes.Clt_Un : CilOpCodes.Clt;
        }
        else
        {
            if (floating && invert) useUn = !useUn;
            operation = useUn ? CilOpCodes.Cgt_Un : CilOpCodes.Cgt;
        }
        Emit(operation);
        if (invert)
            EmitBooleanNot();
    }

    private void EmitBooleanNot()
    {
        Emit(CilOpCodes.Ldc_I4_0);
        Emit(CilOpCodes.Ceq);
    }

    private bool TryGetUnorderedBehavior(IReadOnlyList<SymValue> args, out bool unordered)
    {
        unordered = false;
        if (args.Count <= 2)
            return true;
        if (!TryInt(args[2], out int behavior))
            return false;
        // Structurally observed comparison enum: zero takes the unordered-true floating path;
        // nonzero takes the ordered path. Integral comparisons derive signedness from their type.
        unordered = behavior == 0;
        return true;
    }

    private StackComparisonCategory StackComparisonCategoryOf(SymValue value)
    {
        if (IsKnownNullValue(value))
            return StackComparisonCategory.Null;
        TypeSignature? type = KnownTypeOf(value);
        if (type is null)
            return StackComparisonCategory.Unknown;

        TypeDefinition? definition = ResolveTypeDef(type);
        if (definition is { IsEnum: true } && definition.GetEnumUnderlyingType() is { } underlying)
            type = underlying;
        if (type.IsTypeOf("System", "SByte") || type.IsTypeOf("System", "Int16")
            || type.IsTypeOf("System", "Int32")) return StackComparisonCategory.I4Signed;
        if (type.IsTypeOf("System", "Boolean") || type.IsTypeOf("System", "Char")
            || type.IsTypeOf("System", "Byte") || type.IsTypeOf("System", "UInt16")
            || type.IsTypeOf("System", "UInt32")) return StackComparisonCategory.I4Unsigned;
        if (type.IsTypeOf("System", "Int64")) return StackComparisonCategory.I8Signed;
        if (type.IsTypeOf("System", "UInt64")) return StackComparisonCategory.I8Unsigned;
        if (type.IsTypeOf("System", "IntPtr")) return StackComparisonCategory.NativeSigned;
        if (type.IsTypeOf("System", "UIntPtr")) return StackComparisonCategory.NativeUnsigned;
        if (type.IsTypeOf("System", "Single") || type.IsTypeOf("System", "Double"))
            return StackComparisonCategory.Float;
        try { return !type.IsValueType ? StackComparisonCategory.Reference : StackComparisonCategory.Unknown; }
        catch { return StackComparisonCategory.Unknown; }
    }

    private static bool AreEqualityCompatible(StackComparisonCategory left, StackComparisonCategory right) =>
        AreNumericCompatible(left, right)
        || left is StackComparisonCategory.Reference or StackComparisonCategory.Null
            && right is StackComparisonCategory.Reference or StackComparisonCategory.Null;

    private static bool AreNumericCompatible(StackComparisonCategory left, StackComparisonCategory right) =>
        NumericFamily(left) != 0 && NumericFamily(left) == NumericFamily(right);

    private static int NumericFamily(StackComparisonCategory category) => category switch
    {
        StackComparisonCategory.I4Signed or StackComparisonCategory.I4Unsigned => 1,
        StackComparisonCategory.I8Signed or StackComparisonCategory.I8Unsigned => 2,
        StackComparisonCategory.NativeSigned or StackComparisonCategory.NativeUnsigned => 3,
        StackComparisonCategory.Float => 4,
        _ => 0,
    };

    private static bool IsUnsigned(StackComparisonCategory category) => category is
        StackComparisonCategory.I4Unsigned or StackComparisonCategory.I8Unsigned
        or StackComparisonCategory.NativeUnsigned;

    private static bool IsI4StackType(TypeSignature? type) =>
        type is not null && (type.IsTypeOf("System", "Boolean")
            || type.IsTypeOf("System", "Char") || type.IsTypeOf("System", "SByte")
            || type.IsTypeOf("System", "Byte") || type.IsTypeOf("System", "Int16")
            || type.IsTypeOf("System", "UInt16") || type.IsTypeOf("System", "Int32")
            || type.IsTypeOf("System", "UInt32"));

    private static bool IsKnownNullValue(SymValue value) => value switch
    {
        SymValue.Operand { Value: null } or SymValue.Constant { Value: null } => true,
        SymValue.OnStack { KnownNull: true } => true,
        SymValue.HandlerLocalAddr address => IsKnownNullValue(address.Value),
        _ => false,
    };

    private enum StackComparisonCategory
    {
        Unknown,
        Null,
        Reference,
        I4Signed,
        I4Unsigned,
        I8Signed,
        I8Unsigned,
        NativeSigned,
        NativeUnsigned,
        Float,
    }
}
