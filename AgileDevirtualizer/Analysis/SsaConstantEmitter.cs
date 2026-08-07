using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

internal static class SsaConstantEmitter
{
    public static CilInstruction Emit(object? value) => value switch
    {
        null => new CilInstruction(CilOpCodes.Ldnull),
        bool item => Int32(item ? 1 : 0),
        byte item => Int32(item),
        sbyte item => Int32(item),
        short item => Int32(item),
        ushort item => Int32(item),
        char item => Int32(item),
        int item => Int32(item),
        uint item => Int32(unchecked((int)item)),
        long item => new CilInstruction(CilOpCodes.Ldc_I8, item),
        ulong item => new CilInstruction(CilOpCodes.Ldc_I8, unchecked((long)item)),
        float item => new CilInstruction(CilOpCodes.Ldc_R4, item),
        double item => new CilInstruction(CilOpCodes.Ldc_R8, item),
        string item => new CilInstruction(CilOpCodes.Ldstr, item),
        _ => throw new InvalidOperationException(
            $"SSA constant of type {value.GetType().FullName} has no CIL materialization"),
    };

    private static CilInstruction Int32(int value) => value switch
    {
        -1 => new CilInstruction(CilOpCodes.Ldc_I4_M1),
        0 => new CilInstruction(CilOpCodes.Ldc_I4_0),
        1 => new CilInstruction(CilOpCodes.Ldc_I4_1),
        2 => new CilInstruction(CilOpCodes.Ldc_I4_2),
        3 => new CilInstruction(CilOpCodes.Ldc_I4_3),
        4 => new CilInstruction(CilOpCodes.Ldc_I4_4),
        5 => new CilInstruction(CilOpCodes.Ldc_I4_5),
        6 => new CilInstruction(CilOpCodes.Ldc_I4_6),
        7 => new CilInstruction(CilOpCodes.Ldc_I4_7),
        8 => new CilInstruction(CilOpCodes.Ldc_I4_8),
        >= sbyte.MinValue and <= sbyte.MaxValue =>
            new CilInstruction(CilOpCodes.Ldc_I4_S, (sbyte)value),
        _ => new CilInstruction(CilOpCodes.Ldc_I4, value),
    };
}
