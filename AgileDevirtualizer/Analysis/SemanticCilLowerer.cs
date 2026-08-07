using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>Lowers target-neutral Semantic IR attributes into concrete CIL opcodes.</summary>
internal static class SemanticCilLowerer
{
    public static bool CanLower(SemanticOperation operation) =>
        TryLower(operation, out _);

    public static bool CanLower(SemanticTerminator terminator) =>
        TryLower(terminator, isLeave: false, out _);

    public static CilOpCode Lower(SemanticOperation operation) =>
        TryLower(operation, out var opCode)
            ? opCode
            : throw new InvalidOperationException(
                $"semantic operation {operation.Code} / {operation.Semantics} has no CIL lowering");

    public static CilOpCode Lower(SemanticTerminator terminator, bool isLeave) =>
        TryLower(terminator, isLeave, out var opCode)
            ? opCode
            : throw new InvalidOperationException(
                $"semantic terminator {terminator.Kind} / {terminator.Semantics} has no CIL lowering");

    private static bool TryLower(SemanticOperation operation, out CilOpCode opCode)
    {
        try
        {
            opCode = operation.Code switch
            {
                SemanticOperationCode.Nop => CilOpCodes.Nop,
                SemanticOperationCode.LoadConstant => Constant(operation),
                SemanticOperationCode.LoadNull => CilOpCodes.Ldnull,
                SemanticOperationCode.LoadString => CilOpCodes.Ldstr,
                SemanticOperationCode.LoadToken => CilOpCodes.Ldtoken,
                SemanticOperationCode.LoadFunctionPointer => operation.Semantics.Dispatch switch
                {
                    SemanticDispatchKind.Direct => CilOpCodes.Ldftn,
                    SemanticDispatchKind.Virtual => CilOpCodes.Ldvirtftn,
                    _ => throw Missing(),
                },
                SemanticOperationCode.LoadArgument => Variable(operation, CilOpCodes.Ldarg,
                    CilOpCodes.Ldarg_S, [CilOpCodes.Ldarg_0, CilOpCodes.Ldarg_1,
                        CilOpCodes.Ldarg_2, CilOpCodes.Ldarg_3]),
                SemanticOperationCode.LoadArgumentAddress => Variable(operation,
                    CilOpCodes.Ldarga, CilOpCodes.Ldarga_S),
                SemanticOperationCode.StoreArgument => Variable(operation,
                    CilOpCodes.Starg, CilOpCodes.Starg_S),
                SemanticOperationCode.LoadLocal => Variable(operation, CilOpCodes.Ldloc,
                    CilOpCodes.Ldloc_S, [CilOpCodes.Ldloc_0, CilOpCodes.Ldloc_1,
                        CilOpCodes.Ldloc_2, CilOpCodes.Ldloc_3]),
                SemanticOperationCode.LoadLocalAddress => Variable(operation,
                    CilOpCodes.Ldloca, CilOpCodes.Ldloca_S),
                SemanticOperationCode.StoreLocal => Variable(operation, CilOpCodes.Stloc,
                    CilOpCodes.Stloc_S, [CilOpCodes.Stloc_0, CilOpCodes.Stloc_1,
                        CilOpCodes.Stloc_2, CilOpCodes.Stloc_3]),
                SemanticOperationCode.LoadField => CilOpCodes.Ldfld,
                SemanticOperationCode.LoadStaticField => CilOpCodes.Ldsfld,
                SemanticOperationCode.StoreField => CilOpCodes.Stfld,
                SemanticOperationCode.StoreStaticField => CilOpCodes.Stsfld,
                SemanticOperationCode.LoadElement => Element(operation.Semantics.PrimitiveType, load: true),
                SemanticOperationCode.LoadElementAddress => CilOpCodes.Ldelema,
                SemanticOperationCode.StoreElement => Element(operation.Semantics.PrimitiveType, load: false),
                SemanticOperationCode.LoadObject => CilOpCodes.Ldobj,
                SemanticOperationCode.StoreObject => CilOpCodes.Stobj,
                SemanticOperationCode.LoadArrayLength => CilOpCodes.Ldlen,
                SemanticOperationCode.NewArray => CilOpCodes.Newarr,
                SemanticOperationCode.Add => Arithmetic(operation, CilOpCodes.Add,
                    CilOpCodes.Add_Ovf, CilOpCodes.Add_Ovf_Un),
                SemanticOperationCode.Subtract => Arithmetic(operation, CilOpCodes.Sub,
                    CilOpCodes.Sub_Ovf, CilOpCodes.Sub_Ovf_Un),
                SemanticOperationCode.Multiply => Arithmetic(operation, CilOpCodes.Mul,
                    CilOpCodes.Mul_Ovf, CilOpCodes.Mul_Ovf_Un),
                SemanticOperationCode.Divide => Signed(operation, CilOpCodes.Div, CilOpCodes.Div_Un),
                SemanticOperationCode.Remainder => Signed(operation, CilOpCodes.Rem, CilOpCodes.Rem_Un),
                SemanticOperationCode.BitwiseAnd => CilOpCodes.And,
                SemanticOperationCode.BitwiseOr => CilOpCodes.Or,
                SemanticOperationCode.BitwiseXor => CilOpCodes.Xor,
                SemanticOperationCode.ShiftLeft => CilOpCodes.Shl,
                SemanticOperationCode.ShiftRight => Signed(operation, CilOpCodes.Shr, CilOpCodes.Shr_Un),
                SemanticOperationCode.Negate => CilOpCodes.Neg,
                SemanticOperationCode.BitwiseNot => CilOpCodes.Not,
                SemanticOperationCode.CompareEqual => CilOpCodes.Ceq,
                SemanticOperationCode.CompareLessThan => Comparison(operation,
                    CilOpCodes.Clt, CilOpCodes.Clt_Un),
                SemanticOperationCode.CompareGreaterThan => Comparison(operation,
                    CilOpCodes.Cgt, CilOpCodes.Cgt_Un),
                SemanticOperationCode.Convert => Convert(operation.Semantics),
                SemanticOperationCode.Box => CilOpCodes.Box,
                SemanticOperationCode.UnboxAddress => CilOpCodes.Unbox,
                SemanticOperationCode.UnboxValue => CilOpCodes.Unbox_Any,
                SemanticOperationCode.Cast => CilOpCodes.Castclass,
                SemanticOperationCode.IsInstance => CilOpCodes.Isinst,
                SemanticOperationCode.Call => CilOpCodes.Call,
                SemanticOperationCode.CallVirtual => CilOpCodes.Callvirt,
                SemanticOperationCode.NewObject => CilOpCodes.Newobj,
                SemanticOperationCode.Duplicate => CilOpCodes.Dup,
                SemanticOperationCode.Pop => CilOpCodes.Pop,
                SemanticOperationCode.InitializeObject => CilOpCodes.Initobj,
                SemanticOperationCode.Prefix => Prefix(operation.Semantics.Prefix),
                _ => throw Missing(),
            };
            return true;
        }
        catch (InvalidOperationException)
        {
            opCode = default;
            return false;
        }
    }

    private static bool TryLower(
        SemanticTerminator terminator,
        bool isLeave,
        out CilOpCode opCode)
    {
        try
        {
            opCode = terminator.Kind switch
            {
                SemanticTerminatorKind.Branch when isLeave =>
                    Short(terminator) ? CilOpCodes.Leave_S : CilOpCodes.Leave,
                SemanticTerminatorKind.Branch =>
                    Short(terminator) ? CilOpCodes.Br_S : CilOpCodes.Br,
                SemanticTerminatorKind.Conditional => Conditional(terminator.Semantics),
                SemanticTerminatorKind.Switch => CilOpCodes.Switch,
                SemanticTerminatorKind.Return => CilOpCodes.Ret,
                SemanticTerminatorKind.Throw => CilOpCodes.Throw,
                SemanticTerminatorKind.Rethrow => CilOpCodes.Rethrow,
                SemanticTerminatorKind.EndFinally => CilOpCodes.Endfinally,
                SemanticTerminatorKind.EndFilter => CilOpCodes.Endfilter,
                _ => throw Missing(),
            };
            return true;
        }
        catch (InvalidOperationException)
        {
            opCode = default;
            return false;
        }
    }

    private static CilOpCode Constant(SemanticOperation operation)
    {
        var semantics = operation.Semantics;
        if (semantics.PrimitiveType == SemanticPrimitiveType.Int32
            && semantics.Encoding == SemanticOperandEncoding.Implicit)
        {
            return System.Convert.ToInt32(operation.Operand) switch
            {
                -1 => CilOpCodes.Ldc_I4_M1,
                0 => CilOpCodes.Ldc_I4_0,
                1 => CilOpCodes.Ldc_I4_1,
                2 => CilOpCodes.Ldc_I4_2,
                3 => CilOpCodes.Ldc_I4_3,
                4 => CilOpCodes.Ldc_I4_4,
                5 => CilOpCodes.Ldc_I4_5,
                6 => CilOpCodes.Ldc_I4_6,
                7 => CilOpCodes.Ldc_I4_7,
                8 => CilOpCodes.Ldc_I4_8,
                _ => throw Missing(),
            };
        }
        return (semantics.PrimitiveType, semantics.Encoding) switch
        {
            (SemanticPrimitiveType.Int32, SemanticOperandEncoding.ShortInline) => CilOpCodes.Ldc_I4_S,
            (SemanticPrimitiveType.Int32, SemanticOperandEncoding.Inline) => CilOpCodes.Ldc_I4,
            (SemanticPrimitiveType.Int64, SemanticOperandEncoding.Inline) => CilOpCodes.Ldc_I8,
            (SemanticPrimitiveType.Float32, SemanticOperandEncoding.ShortInline) => CilOpCodes.Ldc_R4,
            (SemanticPrimitiveType.Float64, SemanticOperandEncoding.Inline) => CilOpCodes.Ldc_R8,
            _ => throw Missing(),
        };
    }

    private static CilOpCode Variable(
        SemanticOperation operation,
        CilOpCode inline,
        CilOpCode shortInline,
        IReadOnlyList<CilOpCode>? implicitForms = null) => operation.Semantics.Encoding switch
    {
        SemanticOperandEncoding.Inline => inline,
        SemanticOperandEncoding.ShortInline => shortInline,
        SemanticOperandEncoding.Implicit when implicitForms is not null
            && VariableIndex(operation.Operand) is var index
            && index >= 0 && index <= 3 => implicitForms[index],
        _ => throw Missing(),
    };

    private static int VariableIndex(object? operand) => operand switch
    {
        SemanticLocalReference local => local.Index,
        SemanticArgumentReference argument => argument.Index,
        _ => -1,
    };

    private static CilOpCode Element(SemanticPrimitiveType type, bool load) => (load, type) switch
    {
        (true, SemanticPrimitiveType.Int8) => CilOpCodes.Ldelem_I1,
        (true, SemanticPrimitiveType.UInt8) => CilOpCodes.Ldelem_U1,
        (true, SemanticPrimitiveType.Int16) => CilOpCodes.Ldelem_I2,
        (true, SemanticPrimitiveType.UInt16) => CilOpCodes.Ldelem_U2,
        (true, SemanticPrimitiveType.Int32) => CilOpCodes.Ldelem_I4,
        (true, SemanticPrimitiveType.UInt32) => CilOpCodes.Ldelem_U4,
        (true, SemanticPrimitiveType.Int64) => CilOpCodes.Ldelem_I8,
        (true, SemanticPrimitiveType.NativeInt) => CilOpCodes.Ldelem_I,
        (true, SemanticPrimitiveType.Float32) => CilOpCodes.Ldelem_R4,
        (true, SemanticPrimitiveType.Float64) => CilOpCodes.Ldelem_R8,
        (true, SemanticPrimitiveType.Reference) => CilOpCodes.Ldelem_Ref,
        (true, SemanticPrimitiveType.Typed) => CilOpCodes.Ldelem,
        (false, SemanticPrimitiveType.Int8) => CilOpCodes.Stelem_I1,
        (false, SemanticPrimitiveType.Int16) => CilOpCodes.Stelem_I2,
        (false, SemanticPrimitiveType.Int32) => CilOpCodes.Stelem_I4,
        (false, SemanticPrimitiveType.Int64) => CilOpCodes.Stelem_I8,
        (false, SemanticPrimitiveType.NativeInt) => CilOpCodes.Stelem_I,
        (false, SemanticPrimitiveType.Float32) => CilOpCodes.Stelem_R4,
        (false, SemanticPrimitiveType.Float64) => CilOpCodes.Stelem_R8,
        (false, SemanticPrimitiveType.Reference) => CilOpCodes.Stelem_Ref,
        (false, SemanticPrimitiveType.Typed) => CilOpCodes.Stelem,
        _ => throw Missing(),
    };

    private static CilOpCode Arithmetic(
        SemanticOperation operation,
        CilOpCode uncheckedCode,
        CilOpCode checkedSigned,
        CilOpCode checkedUnsigned) => operation.Semantics.Overflow switch
    {
        SemanticOverflowMode.Unchecked => uncheckedCode,
        SemanticOverflowMode.Checked when operation.Semantics.Signedness == SemanticSignedness.Signed
            => checkedSigned,
        SemanticOverflowMode.Checked when operation.Semantics.Signedness == SemanticSignedness.Unsigned
            => checkedUnsigned,
        _ => throw Missing(),
    };

    private static CilOpCode Signed(
        SemanticOperation operation,
        CilOpCode signed,
        CilOpCode unsigned) => operation.Semantics.Signedness switch
    {
        SemanticSignedness.Signed => signed,
        SemanticSignedness.Unsigned => unsigned,
        _ => throw Missing(),
    };

    private static CilOpCode Comparison(
        SemanticOperation operation,
        CilOpCode signedOrdered,
        CilOpCode unsignedOrUnordered) =>
        (operation.Semantics.Signedness, operation.Semantics.UnorderedFloatingPoint) switch
        {
            (SemanticSignedness.Signed, false) => signedOrdered,
            (SemanticSignedness.Unsigned, true) => unsignedOrUnordered,
            _ => throw Missing(),
        };

    private static CilOpCode Convert(SemanticInstructionSemantics semantics)
    {
        if (semantics.Overflow == SemanticOverflowMode.Unchecked)
        {
            if (semantics.Signedness == SemanticSignedness.Unsigned
                && semantics.PrimitiveType == SemanticPrimitiveType.Float64)
                return CilOpCodes.Conv_R_Un;
            return semantics.PrimitiveType switch
            {
                SemanticPrimitiveType.Int8 => CilOpCodes.Conv_I1,
                SemanticPrimitiveType.UInt8 => CilOpCodes.Conv_U1,
                SemanticPrimitiveType.Int16 => CilOpCodes.Conv_I2,
                SemanticPrimitiveType.UInt16 => CilOpCodes.Conv_U2,
                SemanticPrimitiveType.Int32 => CilOpCodes.Conv_I4,
                SemanticPrimitiveType.UInt32 => CilOpCodes.Conv_U4,
                SemanticPrimitiveType.Int64 => CilOpCodes.Conv_I8,
                SemanticPrimitiveType.UInt64 => CilOpCodes.Conv_U8,
                SemanticPrimitiveType.NativeInt => CilOpCodes.Conv_I,
                SemanticPrimitiveType.NativeUInt => CilOpCodes.Conv_U,
                SemanticPrimitiveType.Float32 => CilOpCodes.Conv_R4,
                SemanticPrimitiveType.Float64 => CilOpCodes.Conv_R8,
                _ => throw Missing(),
            };
        }

        bool unsigned = semantics.Signedness == SemanticSignedness.Unsigned;
        return (semantics.PrimitiveType, unsigned) switch
        {
            (SemanticPrimitiveType.NativeInt, false) => CilOpCodes.Conv_Ovf_I,
            (SemanticPrimitiveType.NativeInt, true) => CilOpCodes.Conv_Ovf_I_Un,
            (SemanticPrimitiveType.NativeUInt, false) => CilOpCodes.Conv_Ovf_U,
            (SemanticPrimitiveType.NativeUInt, true) => CilOpCodes.Conv_Ovf_U_Un,
            (SemanticPrimitiveType.Int8, false) => CilOpCodes.Conv_Ovf_I1,
            (SemanticPrimitiveType.Int8, true) => CilOpCodes.Conv_Ovf_I1_Un,
            (SemanticPrimitiveType.UInt8, false) => CilOpCodes.Conv_Ovf_U1,
            (SemanticPrimitiveType.UInt8, true) => CilOpCodes.Conv_Ovf_U1_Un,
            (SemanticPrimitiveType.Int16, false) => CilOpCodes.Conv_Ovf_I2,
            (SemanticPrimitiveType.Int16, true) => CilOpCodes.Conv_Ovf_I2_Un,
            (SemanticPrimitiveType.UInt16, false) => CilOpCodes.Conv_Ovf_U2,
            (SemanticPrimitiveType.UInt16, true) => CilOpCodes.Conv_Ovf_U2_Un,
            (SemanticPrimitiveType.Int32, false) => CilOpCodes.Conv_Ovf_I4,
            (SemanticPrimitiveType.Int32, true) => CilOpCodes.Conv_Ovf_I4_Un,
            (SemanticPrimitiveType.UInt32, false) => CilOpCodes.Conv_Ovf_U4,
            (SemanticPrimitiveType.UInt32, true) => CilOpCodes.Conv_Ovf_U4_Un,
            (SemanticPrimitiveType.Int64, false) => CilOpCodes.Conv_Ovf_I8,
            (SemanticPrimitiveType.Int64, true) => CilOpCodes.Conv_Ovf_I8_Un,
            (SemanticPrimitiveType.UInt64, false) => CilOpCodes.Conv_Ovf_U8,
            (SemanticPrimitiveType.UInt64, true) => CilOpCodes.Conv_Ovf_U8_Un,
            _ => throw Missing(),
        };
    }

    private static CilOpCode Prefix(SemanticPrefixKind prefix) => prefix switch
    {
        SemanticPrefixKind.Constrained => CilOpCodes.Constrained,
        SemanticPrefixKind.Readonly => CilOpCodes.Readonly,
        SemanticPrefixKind.Tail => CilOpCodes.Tailcall,
        SemanticPrefixKind.Volatile => CilOpCodes.Volatile,
        SemanticPrefixKind.Unaligned => CilOpCodes.Unaligned,
        _ => throw Missing(),
    };

    private static CilOpCode Conditional(SemanticTerminatorSemantics semantics)
    {
        bool shortForm = semantics.Encoding == SemanticOperandEncoding.ShortInline;
        bool unsigned = semantics.Signedness == SemanticSignedness.Unsigned;
        bool unordered = semantics.UnorderedFloatingPoint;
        return (semantics.Predicate, unsigned, unordered, shortForm) switch
        {
            (SemanticBranchPredicate.True, false, false, false) => CilOpCodes.Brtrue,
            (SemanticBranchPredicate.True, false, false, true) => CilOpCodes.Brtrue_S,
            (SemanticBranchPredicate.False, false, false, false) => CilOpCodes.Brfalse,
            (SemanticBranchPredicate.False, false, false, true) => CilOpCodes.Brfalse_S,
            (SemanticBranchPredicate.Equal, false, false, false) => CilOpCodes.Beq,
            (SemanticBranchPredicate.Equal, false, false, true) => CilOpCodes.Beq_S,
            (SemanticBranchPredicate.NotEqual, true, true, false) => CilOpCodes.Bne_Un,
            (SemanticBranchPredicate.NotEqual, true, true, true) => CilOpCodes.Bne_Un_S,
            (SemanticBranchPredicate.GreaterThan, false, false, false) => CilOpCodes.Bgt,
            (SemanticBranchPredicate.GreaterThan, false, false, true) => CilOpCodes.Bgt_S,
            (SemanticBranchPredicate.GreaterThan, true, true, false) => CilOpCodes.Bgt_Un,
            (SemanticBranchPredicate.GreaterThan, true, true, true) => CilOpCodes.Bgt_Un_S,
            (SemanticBranchPredicate.GreaterThanOrEqual, false, false, false) => CilOpCodes.Bge,
            (SemanticBranchPredicate.GreaterThanOrEqual, false, false, true) => CilOpCodes.Bge_S,
            (SemanticBranchPredicate.GreaterThanOrEqual, true, true, false) => CilOpCodes.Bge_Un,
            (SemanticBranchPredicate.GreaterThanOrEqual, true, true, true) => CilOpCodes.Bge_Un_S,
            (SemanticBranchPredicate.LessThan, false, false, false) => CilOpCodes.Blt,
            (SemanticBranchPredicate.LessThan, false, false, true) => CilOpCodes.Blt_S,
            (SemanticBranchPredicate.LessThan, true, true, false) => CilOpCodes.Blt_Un,
            (SemanticBranchPredicate.LessThan, true, true, true) => CilOpCodes.Blt_Un_S,
            (SemanticBranchPredicate.LessThanOrEqual, false, false, false) => CilOpCodes.Ble,
            (SemanticBranchPredicate.LessThanOrEqual, false, false, true) => CilOpCodes.Ble_S,
            (SemanticBranchPredicate.LessThanOrEqual, true, true, false) => CilOpCodes.Ble_Un,
            (SemanticBranchPredicate.LessThanOrEqual, true, true, true) => CilOpCodes.Ble_Un_S,
            _ => throw Missing(),
        };
    }

    private static bool Short(SemanticTerminator terminator) =>
        terminator.Semantics.Encoding == SemanticOperandEncoding.ShortInline;

    private static InvalidOperationException Missing() =>
        new("semantic CIL lowering is not defined");
}
