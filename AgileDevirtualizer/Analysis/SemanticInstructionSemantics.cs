using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

internal enum SemanticSignedness
{
    None,
    Signed,
    Unsigned,
}

internal enum SemanticOverflowMode
{
    Unchecked,
    Checked,
}

internal enum SemanticPrimitiveType
{
    None,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    NativeInt,
    NativeUInt,
    Float32,
    Float64,
    Reference,
    Typed,
}

internal enum SemanticOperandEncoding
{
    Default,
    Implicit,
    ShortInline,
    Inline,
}

internal enum SemanticDispatchKind
{
    None,
    Direct,
    Virtual,
}

internal enum SemanticPrefixKind
{
    None,
    Constrained,
    Readonly,
    Tail,
    Volatile,
    Unaligned,
}

internal readonly record struct SemanticInstructionSemantics(
    SemanticSignedness Signedness = SemanticSignedness.None,
    SemanticOverflowMode Overflow = SemanticOverflowMode.Unchecked,
    SemanticPrimitiveType PrimitiveType = SemanticPrimitiveType.None,
    SemanticOperandEncoding Encoding = SemanticOperandEncoding.Default,
    SemanticDispatchKind Dispatch = SemanticDispatchKind.None,
    SemanticPrefixKind Prefix = SemanticPrefixKind.None,
    bool UnorderedFloatingPoint = false);

internal enum SemanticBranchPredicate
{
    None,
    Always,
    True,
    False,
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

internal readonly record struct SemanticTerminatorSemantics(
    SemanticBranchPredicate Predicate = SemanticBranchPredicate.None,
    SemanticSignedness Signedness = SemanticSignedness.None,
    SemanticOperandEncoding Encoding = SemanticOperandEncoding.Default,
    bool UnorderedFloatingPoint = false);

/// <summary>
/// Boundary adapter from recovered CIL into target-neutral semantic attributes. No AsmResolver
/// opcode escapes into Semantic IR; the reverse mapping lives independently in SemanticCilLowerer.
/// </summary>
internal static class SemanticInstructionSemanticsAdapter
{
    public static SemanticInstructionSemantics ForOperation(CilCode code) => code switch
    {
        CilCode.Ldc_I4_M1 or CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2
            or CilCode.Ldc_I4_3 or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5 or CilCode.Ldc_I4_6
            or CilCode.Ldc_I4_7 or CilCode.Ldc_I4_8 =>
            S(type: SemanticPrimitiveType.Int32, encoding: SemanticOperandEncoding.Implicit),
        CilCode.Ldc_I4_S =>
            S(type: SemanticPrimitiveType.Int32, encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Ldc_I4 =>
            S(type: SemanticPrimitiveType.Int32, encoding: SemanticOperandEncoding.Inline),
        CilCode.Ldc_I8 => S(type: SemanticPrimitiveType.Int64, encoding: SemanticOperandEncoding.Inline),
        CilCode.Ldc_R4 => S(type: SemanticPrimitiveType.Float32, encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Ldc_R8 => S(type: SemanticPrimitiveType.Float64, encoding: SemanticOperandEncoding.Inline),

        CilCode.Ldarg_0 or CilCode.Ldarg_1 or CilCode.Ldarg_2 or CilCode.Ldarg_3
            or CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3
            or CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3 =>
            S(encoding: SemanticOperandEncoding.Implicit),
        CilCode.Ldarg_S or CilCode.Ldarga_S or CilCode.Starg_S
            or CilCode.Ldloc_S or CilCode.Ldloca_S or CilCode.Stloc_S =>
            S(encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Ldarg or CilCode.Ldarga or CilCode.Starg
            or CilCode.Ldloc or CilCode.Ldloca or CilCode.Stloc =>
            S(encoding: SemanticOperandEncoding.Inline),

        CilCode.Ldftn => S(dispatch: SemanticDispatchKind.Direct),
        CilCode.Ldvirtftn => S(dispatch: SemanticDispatchKind.Virtual),
        CilCode.Div or CilCode.Rem or CilCode.Shr or CilCode.Cgt or CilCode.Clt =>
            S(signedness: SemanticSignedness.Signed),
        CilCode.Div_Un or CilCode.Rem_Un or CilCode.Shr_Un =>
            S(signedness: SemanticSignedness.Unsigned),
        CilCode.Cgt_Un or CilCode.Clt_Un =>
            S(signedness: SemanticSignedness.Unsigned, unorderedFloatingPoint: true),
        CilCode.Add_Ovf or CilCode.Sub_Ovf or CilCode.Mul_Ovf =>
            S(signedness: SemanticSignedness.Signed, overflow: SemanticOverflowMode.Checked),
        CilCode.Add_Ovf_Un or CilCode.Sub_Ovf_Un or CilCode.Mul_Ovf_Un =>
            S(signedness: SemanticSignedness.Unsigned, overflow: SemanticOverflowMode.Checked),

        CilCode.Ldelem_I1 or CilCode.Stelem_I1 => S(type: SemanticPrimitiveType.Int8),
        CilCode.Ldelem_U1 => S(type: SemanticPrimitiveType.UInt8),
        CilCode.Ldelem_I2 or CilCode.Stelem_I2 => S(type: SemanticPrimitiveType.Int16),
        CilCode.Ldelem_U2 => S(type: SemanticPrimitiveType.UInt16),
        CilCode.Ldelem_I4 or CilCode.Stelem_I4 => S(type: SemanticPrimitiveType.Int32),
        CilCode.Ldelem_U4 => S(type: SemanticPrimitiveType.UInt32),
        CilCode.Ldelem_I8 or CilCode.Stelem_I8 => S(type: SemanticPrimitiveType.Int64),
        CilCode.Ldelem_I or CilCode.Stelem_I => S(type: SemanticPrimitiveType.NativeInt),
        CilCode.Ldelem_R4 or CilCode.Stelem_R4 => S(type: SemanticPrimitiveType.Float32),
        CilCode.Ldelem_R8 or CilCode.Stelem_R8 => S(type: SemanticPrimitiveType.Float64),
        CilCode.Ldelem_Ref or CilCode.Stelem_Ref => S(type: SemanticPrimitiveType.Reference),
        CilCode.Ldelem or CilCode.Stelem => S(type: SemanticPrimitiveType.Typed),

        CilCode.Conv_I1 => S(type: SemanticPrimitiveType.Int8),
        CilCode.Conv_U1 => S(type: SemanticPrimitiveType.UInt8),
        CilCode.Conv_I2 => S(type: SemanticPrimitiveType.Int16),
        CilCode.Conv_U2 => S(type: SemanticPrimitiveType.UInt16),
        CilCode.Conv_I4 => S(type: SemanticPrimitiveType.Int32),
        CilCode.Conv_U4 => S(type: SemanticPrimitiveType.UInt32),
        CilCode.Conv_I8 => S(type: SemanticPrimitiveType.Int64),
        CilCode.Conv_U8 => S(type: SemanticPrimitiveType.UInt64),
        CilCode.Conv_I => S(type: SemanticPrimitiveType.NativeInt),
        CilCode.Conv_U => S(type: SemanticPrimitiveType.NativeUInt),
        CilCode.Conv_R4 => S(type: SemanticPrimitiveType.Float32),
        CilCode.Conv_R8 => S(type: SemanticPrimitiveType.Float64),
        CilCode.Conv_R_Un => S(signedness: SemanticSignedness.Unsigned,
            type: SemanticPrimitiveType.Float64),
        _ when IsCheckedConversion(code) => CheckedConversion(code),

        CilCode.Constrained => S(prefix: SemanticPrefixKind.Constrained),
        CilCode.Readonly => S(prefix: SemanticPrefixKind.Readonly),
        CilCode.Tailcall => S(prefix: SemanticPrefixKind.Tail),
        CilCode.Volatile => S(prefix: SemanticPrefixKind.Volatile),
        CilCode.Unaligned => S(prefix: SemanticPrefixKind.Unaligned,
            encoding: SemanticOperandEncoding.ShortInline),
        _ => default,
    };

    public static SemanticTerminatorSemantics ForTerminator(CilCode code) => code switch
    {
        CilCode.Br or CilCode.Leave => T(SemanticBranchPredicate.Always),
        CilCode.Br_S or CilCode.Leave_S => T(SemanticBranchPredicate.Always,
            encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Brtrue => T(SemanticBranchPredicate.True),
        CilCode.Brtrue_S => T(SemanticBranchPredicate.True,
            encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Brfalse => T(SemanticBranchPredicate.False),
        CilCode.Brfalse_S => T(SemanticBranchPredicate.False,
            encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Beq => T(SemanticBranchPredicate.Equal),
        CilCode.Beq_S => T(SemanticBranchPredicate.Equal,
            encoding: SemanticOperandEncoding.ShortInline),
        CilCode.Bne_Un => T(SemanticBranchPredicate.NotEqual, SemanticSignedness.Unsigned,
            unorderedFloatingPoint: true),
        CilCode.Bne_Un_S => T(SemanticBranchPredicate.NotEqual, SemanticSignedness.Unsigned,
            SemanticOperandEncoding.ShortInline, unorderedFloatingPoint: true),
        CilCode.Bgt => T(SemanticBranchPredicate.GreaterThan, SemanticSignedness.Signed),
        CilCode.Bgt_S => T(SemanticBranchPredicate.GreaterThan, SemanticSignedness.Signed,
            SemanticOperandEncoding.ShortInline),
        CilCode.Bgt_Un => T(SemanticBranchPredicate.GreaterThan, SemanticSignedness.Unsigned,
            unorderedFloatingPoint: true),
        CilCode.Bgt_Un_S => T(SemanticBranchPredicate.GreaterThan, SemanticSignedness.Unsigned,
            SemanticOperandEncoding.ShortInline, unorderedFloatingPoint: true),
        CilCode.Bge => T(SemanticBranchPredicate.GreaterThanOrEqual, SemanticSignedness.Signed),
        CilCode.Bge_S => T(SemanticBranchPredicate.GreaterThanOrEqual, SemanticSignedness.Signed,
            SemanticOperandEncoding.ShortInline),
        CilCode.Bge_Un => T(SemanticBranchPredicate.GreaterThanOrEqual, SemanticSignedness.Unsigned,
            unorderedFloatingPoint: true),
        CilCode.Bge_Un_S => T(SemanticBranchPredicate.GreaterThanOrEqual, SemanticSignedness.Unsigned,
            SemanticOperandEncoding.ShortInline, unorderedFloatingPoint: true),
        CilCode.Blt => T(SemanticBranchPredicate.LessThan, SemanticSignedness.Signed),
        CilCode.Blt_S => T(SemanticBranchPredicate.LessThan, SemanticSignedness.Signed,
            SemanticOperandEncoding.ShortInline),
        CilCode.Blt_Un => T(SemanticBranchPredicate.LessThan, SemanticSignedness.Unsigned,
            unorderedFloatingPoint: true),
        CilCode.Blt_Un_S => T(SemanticBranchPredicate.LessThan, SemanticSignedness.Unsigned,
            SemanticOperandEncoding.ShortInline, unorderedFloatingPoint: true),
        CilCode.Ble => T(SemanticBranchPredicate.LessThanOrEqual, SemanticSignedness.Signed),
        CilCode.Ble_S => T(SemanticBranchPredicate.LessThanOrEqual, SemanticSignedness.Signed,
            SemanticOperandEncoding.ShortInline),
        CilCode.Ble_Un => T(SemanticBranchPredicate.LessThanOrEqual, SemanticSignedness.Unsigned,
            unorderedFloatingPoint: true),
        CilCode.Ble_Un_S => T(SemanticBranchPredicate.LessThanOrEqual, SemanticSignedness.Unsigned,
            SemanticOperandEncoding.ShortInline, unorderedFloatingPoint: true),
        CilCode.Switch => T(SemanticBranchPredicate.None, encoding: SemanticOperandEncoding.Inline),
        _ => default,
    };

    private static SemanticInstructionSemantics S(
        SemanticSignedness signedness = SemanticSignedness.None,
        SemanticOverflowMode overflow = SemanticOverflowMode.Unchecked,
        SemanticPrimitiveType type = SemanticPrimitiveType.None,
        SemanticOperandEncoding encoding = SemanticOperandEncoding.Default,
        SemanticDispatchKind dispatch = SemanticDispatchKind.None,
        SemanticPrefixKind prefix = SemanticPrefixKind.None,
        bool unorderedFloatingPoint = false) =>
        new(signedness, overflow, type, encoding, dispatch, prefix, unorderedFloatingPoint);

    private static SemanticTerminatorSemantics T(
        SemanticBranchPredicate predicate,
        SemanticSignedness signedness = SemanticSignedness.None,
        SemanticOperandEncoding encoding = SemanticOperandEncoding.Inline,
        bool unorderedFloatingPoint = false) =>
        new(predicate, signedness, encoding, unorderedFloatingPoint);

    private static bool IsCheckedConversion(CilCode code) => code is
        CilCode.Conv_Ovf_I or CilCode.Conv_Ovf_U or CilCode.Conv_Ovf_I1 or CilCode.Conv_Ovf_U1
        or CilCode.Conv_Ovf_I2 or CilCode.Conv_Ovf_U2 or CilCode.Conv_Ovf_I4 or CilCode.Conv_Ovf_U4
        or CilCode.Conv_Ovf_I8 or CilCode.Conv_Ovf_U8 or CilCode.Conv_Ovf_I_Un or CilCode.Conv_Ovf_U_Un
        or CilCode.Conv_Ovf_I1_Un or CilCode.Conv_Ovf_U1_Un or CilCode.Conv_Ovf_I2_Un
        or CilCode.Conv_Ovf_U2_Un or CilCode.Conv_Ovf_I4_Un or CilCode.Conv_Ovf_U4_Un
        or CilCode.Conv_Ovf_I8_Un or CilCode.Conv_Ovf_U8_Un;

    private static SemanticInstructionSemantics CheckedConversion(CilCode code)
    {
        var signedness = code is CilCode.Conv_Ovf_I_Un or CilCode.Conv_Ovf_U_Un
            or CilCode.Conv_Ovf_I1_Un or CilCode.Conv_Ovf_U1_Un
            or CilCode.Conv_Ovf_I2_Un or CilCode.Conv_Ovf_U2_Un
            or CilCode.Conv_Ovf_I4_Un or CilCode.Conv_Ovf_U4_Un
            or CilCode.Conv_Ovf_I8_Un or CilCode.Conv_Ovf_U8_Un
            ? SemanticSignedness.Unsigned : SemanticSignedness.Signed;
        var type = code switch
        {
            CilCode.Conv_Ovf_I or CilCode.Conv_Ovf_I_Un => SemanticPrimitiveType.NativeInt,
            CilCode.Conv_Ovf_U or CilCode.Conv_Ovf_U_Un => SemanticPrimitiveType.NativeUInt,
            CilCode.Conv_Ovf_I1 or CilCode.Conv_Ovf_I1_Un => SemanticPrimitiveType.Int8,
            CilCode.Conv_Ovf_U1 or CilCode.Conv_Ovf_U1_Un => SemanticPrimitiveType.UInt8,
            CilCode.Conv_Ovf_I2 or CilCode.Conv_Ovf_I2_Un => SemanticPrimitiveType.Int16,
            CilCode.Conv_Ovf_U2 or CilCode.Conv_Ovf_U2_Un => SemanticPrimitiveType.UInt16,
            CilCode.Conv_Ovf_I4 or CilCode.Conv_Ovf_I4_Un => SemanticPrimitiveType.Int32,
            CilCode.Conv_Ovf_U4 or CilCode.Conv_Ovf_U4_Un => SemanticPrimitiveType.UInt32,
            CilCode.Conv_Ovf_I8 or CilCode.Conv_Ovf_I8_Un => SemanticPrimitiveType.Int64,
            CilCode.Conv_Ovf_U8 or CilCode.Conv_Ovf_U8_Un => SemanticPrimitiveType.UInt64,
            _ => SemanticPrimitiveType.None,
        };
        return S(signedness, SemanticOverflowMode.Checked, type);
    }
}
