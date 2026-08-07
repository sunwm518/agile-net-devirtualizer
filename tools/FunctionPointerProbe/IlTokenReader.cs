using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;

internal static class IlTokenReader
{
    private static readonly Dictionary<ushort, OpCode> OpCodesByValue = typeof(OpCodes)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field.FieldType == typeof(OpCode))
        .Select(field => (OpCode)field.GetValue(null))
        .ToDictionary(opcode => unchecked((ushort)opcode.Value));

    public static IReadOnlyList<MethodInfo> FunctionPointers(MethodInfo method) =>
        Tokens(method, OpCodes.Ldftn).Select(token => method.Module.ResolveMethod(token,
            method.DeclaringType?.GetGenericArguments(), method.GetGenericArguments()))
        .OfType<MethodInfo>().ToArray();

    public static IReadOnlyList<FieldInfo> StaticFieldLoads(MethodInfo method) =>
        Tokens(method, OpCodes.Ldsfld).Select(token => method.Module.ResolveField(token,
            method.DeclaringType?.GetGenericArguments(), method.GetGenericArguments()))
        .Where(field => field.IsStatic).Distinct().ToArray();

    private static IEnumerable<int> Tokens(MethodInfo method, OpCode selected)
    {
        byte[] il = method.GetMethodBody()?.GetILAsByteArray()
            ?? throw new InvalidOperationException("method has no CIL body");
        for (int offset = 0; offset < il.Length;)
        {
            OpCode opcode = ReadOpCode(il, ref offset);
            int operandSize = OperandSize(opcode.OperandType, il, offset);
            if (opcode == selected)
                yield return BitConverter.ToInt32(il, offset);
            offset += operandSize;
        }
    }

    private static OpCode ReadOpCode(byte[] il, ref int offset)
    {
        ushort value = il[offset++];
        if (value == 0xFE)
            value = (ushort)(0xFE00 | il[offset++]);
        return OpCodesByValue.TryGetValue(value, out var opcode)
            ? opcode : throw new BadImageFormatException($"unknown opcode 0x{value:X4}");
    }

    private static int OperandSize(OperandType type, byte[] il, int offset) => type switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI or OperandType.InlineBrTarget or OperandType.InlineField
            or OperandType.InlineMethod or OperandType.InlineSig or OperandType.InlineString
            or OperandType.InlineTok or OperandType.InlineType or OperandType.ShortInlineR => 4,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => 4 + BitConverter.ToInt32(il, offset) * 4,
        _ => throw new BadImageFormatException($"unsupported operand type {type}"),
    };
}
