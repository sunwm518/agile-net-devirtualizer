using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Collections;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Stack-oriented semantic operations recovered from VM instructions. This is deliberately not a
/// CIL instruction model: opcode families that have the same program meaning share one semantic
/// code. The legacy display is retained only as provenance while the new pipeline is observational.
/// </summary>
internal enum SemanticOperationCode
{
    Nop,
    LoadConstant,
    LoadNull,
    LoadString,
    LoadToken,
    LoadFunctionPointer,
    LoadArgument,
    LoadArgumentAddress,
    StoreArgument,
    LoadLocal,
    LoadLocalAddress,
    StoreLocal,
    LoadField,
    LoadStaticField,
    StoreField,
    StoreStaticField,
    LoadElement,
    LoadElementAddress,
    StoreElement,
    LoadObject,
    StoreObject,
    LoadArrayLength,
    NewArray,
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    ShiftLeft,
    ShiftRight,
    Negate,
    BitwiseNot,
    CompareEqual,
    CompareLessThan,
    CompareGreaterThan,
    Convert,
    Box,
    UnboxAddress,
    UnboxValue,
    Cast,
    IsInstance,
    Call,
    CallVirtual,
    NewObject,
    Duplicate,
    Pop,
    InitializeObject,
    Prefix,
    Other,
}

internal readonly record struct SemanticLocalReference(int Index, bool Temporary);
internal readonly record struct SemanticArgumentReference(int Index);

internal sealed record SemanticOperation(
    int VmInstructionIndex,
    SemanticOperationCode Code,
    object? Operand,
    string LegacyDisplay,
    SemanticInstructionSemantics Semantics = default);

/// <summary>
/// Read-only bridge from the green legacy LiftedOp corpus into semantic IR. Future VM handlers can
/// produce these operations directly; until then the adapter lets the IR/CFG be compared without
/// changing acceptance or emission.
/// </summary>
internal static class LegacySemanticIrAdapter
{
    public static SemanticOperation Convert(int vmInstructionIndex, LiftedOp operation) =>
        new(vmInstructionIndex, Classify(operation.OpCode.Code), NormalizeOperand(operation),
            operation.ToString(),
            SemanticInstructionSemanticsAdapter.ForOperation(operation.OpCode.Code));

    private static object? NormalizeOperand(LiftedOp operation)
    {
        var code = operation.OpCode.Code;
        if (code is CilCode.Ldc_I4_M1) return -1;
        if (code is CilCode.Ldc_I4_0) return 0;
        if (code is CilCode.Ldc_I4_1) return 1;
        if (code is CilCode.Ldc_I4_2) return 2;
        if (code is CilCode.Ldc_I4_3) return 3;
        if (code is CilCode.Ldc_I4_4) return 4;
        if (code is CilCode.Ldc_I4_5) return 5;
        if (code is CilCode.Ldc_I4_6) return 6;
        if (code is CilCode.Ldc_I4_7) return 7;
        if (code is CilCode.Ldc_I4_8) return 8;

        if (code is CilCode.Ldarg_0) return new SemanticArgumentReference(0);
        if (code is CilCode.Ldarg_1) return new SemanticArgumentReference(1);
        if (code is CilCode.Ldarg_2) return new SemanticArgumentReference(2);
        if (code is CilCode.Ldarg_3) return new SemanticArgumentReference(3);
        if (code is CilCode.Ldarg or CilCode.Ldarg_S or CilCode.Ldarga or CilCode.Ldarga_S
            or CilCode.Starg or CilCode.Starg_S)
            return new SemanticArgumentReference(IndexOf(operation.Operand));

        if (code is CilCode.Ldloc_0 or CilCode.Stloc_0) return new SemanticLocalReference(0, false);
        if (code is CilCode.Ldloc_1 or CilCode.Stloc_1) return new SemanticLocalReference(1, false);
        if (code is CilCode.Ldloc_2 or CilCode.Stloc_2) return new SemanticLocalReference(2, false);
        if (code is CilCode.Ldloc_3 or CilCode.Stloc_3) return new SemanticLocalReference(3, false);
        if (code is CilCode.Ldloc or CilCode.Ldloc_S or CilCode.Ldloca or CilCode.Ldloca_S
            or CilCode.Stloc or CilCode.Stloc_S)
            return operation.Operand is TempLocalRef temp
                ? new SemanticLocalReference(temp.Index, true)
                : new SemanticLocalReference(IndexOf(operation.Operand), false);

        return operation.Operand;
    }

    private static int IndexOf(object? operand) => operand switch
    {
        int index => index,
        Parameter parameter => parameter.Index,
        _ => -1,
    };

    private static SemanticOperationCode Classify(CilCode code)
    {
        if (code is CilCode.Ldc_I4_M1 or CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1
            or CilCode.Ldc_I4_2 or CilCode.Ldc_I4_3 or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5
            or CilCode.Ldc_I4_6 or CilCode.Ldc_I4_7 or CilCode.Ldc_I4_8 or CilCode.Ldc_I4
            or CilCode.Ldc_I4_S or CilCode.Ldc_I8 or CilCode.Ldc_R4 or CilCode.Ldc_R8)
            return SemanticOperationCode.LoadConstant;
        if (code is CilCode.Ldarg_0 or CilCode.Ldarg_1 or CilCode.Ldarg_2 or CilCode.Ldarg_3
            or CilCode.Ldarg or CilCode.Ldarg_S)
            return SemanticOperationCode.LoadArgument;
        if (code is CilCode.Ldarga or CilCode.Ldarga_S)
            return SemanticOperationCode.LoadArgumentAddress;
        if (code is CilCode.Starg or CilCode.Starg_S)
            return SemanticOperationCode.StoreArgument;
        if (code is CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3
            or CilCode.Ldloc or CilCode.Ldloc_S)
            return SemanticOperationCode.LoadLocal;
        if (code is CilCode.Ldloca or CilCode.Ldloca_S)
            return SemanticOperationCode.LoadLocalAddress;
        if (code is CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3
            or CilCode.Stloc or CilCode.Stloc_S)
            return SemanticOperationCode.StoreLocal;
        if (code is CilCode.Ldelem or CilCode.Ldelem_I or CilCode.Ldelem_I1 or CilCode.Ldelem_I2
            or CilCode.Ldelem_I4 or CilCode.Ldelem_I8 or CilCode.Ldelem_R4 or CilCode.Ldelem_R8
            or CilCode.Ldelem_Ref or CilCode.Ldelem_U1 or CilCode.Ldelem_U2 or CilCode.Ldelem_U4)
            return SemanticOperationCode.LoadElement;
        if (code is CilCode.Stelem or CilCode.Stelem_I or CilCode.Stelem_I1 or CilCode.Stelem_I2
            or CilCode.Stelem_I4 or CilCode.Stelem_I8 or CilCode.Stelem_R4 or CilCode.Stelem_R8
            or CilCode.Stelem_Ref)
            return SemanticOperationCode.StoreElement;
        if (code is CilCode.Conv_I or CilCode.Conv_I1 or CilCode.Conv_I2 or CilCode.Conv_I4
            or CilCode.Conv_I8 or CilCode.Conv_U or CilCode.Conv_U1 or CilCode.Conv_U2
            or CilCode.Conv_U4 or CilCode.Conv_U8 or CilCode.Conv_R4 or CilCode.Conv_R8
            or CilCode.Conv_R_Un
            or CilCode.Conv_Ovf_I or CilCode.Conv_Ovf_I_Un
            or CilCode.Conv_Ovf_U or CilCode.Conv_Ovf_U_Un
            or CilCode.Conv_Ovf_I1 or CilCode.Conv_Ovf_I1_Un
            or CilCode.Conv_Ovf_U1 or CilCode.Conv_Ovf_U1_Un
            or CilCode.Conv_Ovf_I2 or CilCode.Conv_Ovf_I2_Un
            or CilCode.Conv_Ovf_U2 or CilCode.Conv_Ovf_U2_Un
            or CilCode.Conv_Ovf_I4 or CilCode.Conv_Ovf_I4_Un
            or CilCode.Conv_Ovf_U4 or CilCode.Conv_Ovf_U4_Un
            or CilCode.Conv_Ovf_I8 or CilCode.Conv_Ovf_I8_Un
            or CilCode.Conv_Ovf_U8 or CilCode.Conv_Ovf_U8_Un)
            return SemanticOperationCode.Convert;

        return code switch
        {
            CilCode.Nop => SemanticOperationCode.Nop,
            CilCode.Ldnull => SemanticOperationCode.LoadNull,
            CilCode.Ldstr => SemanticOperationCode.LoadString,
            CilCode.Ldtoken => SemanticOperationCode.LoadToken,
            CilCode.Ldftn or CilCode.Ldvirtftn => SemanticOperationCode.LoadFunctionPointer,
            CilCode.Ldfld => SemanticOperationCode.LoadField,
            CilCode.Ldsfld => SemanticOperationCode.LoadStaticField,
            CilCode.Stfld => SemanticOperationCode.StoreField,
            CilCode.Stsfld => SemanticOperationCode.StoreStaticField,
            CilCode.Ldelema => SemanticOperationCode.LoadElementAddress,
            CilCode.Ldobj => SemanticOperationCode.LoadObject,
            CilCode.Stobj => SemanticOperationCode.StoreObject,
            CilCode.Ldlen => SemanticOperationCode.LoadArrayLength,
            CilCode.Newarr => SemanticOperationCode.NewArray,
            CilCode.Add or CilCode.Add_Ovf or CilCode.Add_Ovf_Un => SemanticOperationCode.Add,
            CilCode.Sub or CilCode.Sub_Ovf or CilCode.Sub_Ovf_Un => SemanticOperationCode.Subtract,
            CilCode.Mul or CilCode.Mul_Ovf or CilCode.Mul_Ovf_Un => SemanticOperationCode.Multiply,
            CilCode.Div or CilCode.Div_Un => SemanticOperationCode.Divide,
            CilCode.Rem or CilCode.Rem_Un => SemanticOperationCode.Remainder,
            CilCode.And => SemanticOperationCode.BitwiseAnd,
            CilCode.Or => SemanticOperationCode.BitwiseOr,
            CilCode.Xor => SemanticOperationCode.BitwiseXor,
            CilCode.Shl => SemanticOperationCode.ShiftLeft,
            CilCode.Shr or CilCode.Shr_Un => SemanticOperationCode.ShiftRight,
            CilCode.Neg => SemanticOperationCode.Negate,
            CilCode.Not => SemanticOperationCode.BitwiseNot,
            CilCode.Ceq => SemanticOperationCode.CompareEqual,
            CilCode.Clt or CilCode.Clt_Un => SemanticOperationCode.CompareLessThan,
            CilCode.Cgt or CilCode.Cgt_Un => SemanticOperationCode.CompareGreaterThan,
            CilCode.Box => SemanticOperationCode.Box,
            CilCode.Unbox => SemanticOperationCode.UnboxAddress,
            CilCode.Unbox_Any => SemanticOperationCode.UnboxValue,
            CilCode.Castclass => SemanticOperationCode.Cast,
            CilCode.Isinst => SemanticOperationCode.IsInstance,
            CilCode.Call => SemanticOperationCode.Call,
            CilCode.Callvirt => SemanticOperationCode.CallVirtual,
            CilCode.Newobj => SemanticOperationCode.NewObject,
            CilCode.Dup => SemanticOperationCode.Duplicate,
            CilCode.Pop => SemanticOperationCode.Pop,
            CilCode.Initobj => SemanticOperationCode.InitializeObject,
            CilCode.Constrained or CilCode.Readonly or CilCode.Tailcall or CilCode.Volatile
                or CilCode.Unaligned => SemanticOperationCode.Prefix,
            _ => SemanticOperationCode.Other,
        };
    }
}
