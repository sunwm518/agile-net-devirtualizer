using System.Buffers.Binary;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

internal enum CilConstantArrayElementKind
{
    Boolean,
    Byte,
    SByte,
    Char,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Single,
    Double,
}

/// <summary>
/// A fully known one-dimensional primitive array. Unwritten elements have their CLR zero value;
/// repeated constant writes are represented by their final value.
/// </summary>
internal sealed record CilConstantArrayPattern(
    int AllocationStart,
    int AllocationStore,
    int InitializationEnd,
    CilLocalVariable Local,
    CilConstantArrayElementKind ElementKind,
    int Length,
    byte[] Data,
    IReadOnlySet<int> InitializationInstructions)
{
    public byte[] Bytes() => ElementKind == CilConstantArrayElementKind.Byte
        ? Data.ToArray()
        : throw new InvalidOperationException("constant array is not System.Byte[]");

    public char[] Chars()
    {
        if (ElementKind != CilConstantArrayElementKind.Char)
            throw new InvalidOperationException("constant array is not System.Char[]");
        var result = new char[Length];
        for (int index = 0; index < result.Length; index++)
            result[index] = (char)BinaryPrimitives.ReadUInt16LittleEndian(
                Data.AsSpan(index * 2, 2));
        return result;
    }
}

/// <summary>
/// Recognises constant primitive-array construction independently of a particular consumer.
/// It intentionally accepts only local-backed arrays and constant, in-range stores.
/// </summary>
internal static class CilConstantArrayPatternReader
{
    private const int MaximumElements = 1_000_000;

    public static bool TryRead(CilMethodBody body, int start,
        out CilConstantArrayPattern pattern)
    {
        pattern = null!;
        if (start < 0 || start + 2 >= body.Instructions.Count
            || !TryInt32(body.Instructions[start], out int length)
            || length < 0 || length > MaximumElements
            || body.Instructions[start + 1].OpCode.Code != CilCode.Newarr
            || !TryElement(body.Instructions[start + 1].Operand,
                out var kind, out int elementSize, out var storeCode)
            || !TryStoredLocal(body, start + 2, out var local))
            return false;

        byte[] data;
        try
        {
            data = new byte[checked(length * elementSize)];
        }
        catch (OverflowException)
        {
            return false;
        }

        var initialization = new HashSet<int>();
        int position = start + 3;
        while (position < body.Instructions.Count && LoadsLocal(body, position, local))
        {
            int writeStart = position++;
            if (position < body.Instructions.Count
                && IsArrayCast(body.Instructions[position], kind))
                position++;
            if (position + 2 >= body.Instructions.Count
                || !TryInt32(body.Instructions[position], out int elementIndex)
                || elementIndex < 0 || elementIndex >= length
                || !TryConstant(body.Instructions[position + 1], kind,
                    data.AsSpan(elementIndex * elementSize, elementSize))
                || body.Instructions[position + 2].OpCode.Code != storeCode)
            {
                position = writeStart;
                break;
            }

            for (int index = writeStart; index <= position + 2; index++)
                initialization.Add(index);
            position += 3;
        }

        pattern = new CilConstantArrayPattern(start, start + 2, position - 1,
            local, kind, length, data, initialization);
        return true;
    }

    internal static bool LoadsLocal(CilMethodBody body, int index, CilLocalVariable local)
    {
        if (index < 0 || index >= body.Instructions.Count)
            return false;
        return LocalAt(body, body.Instructions[index], load: true) is { } found
            && ReferenceEquals(found, local);
    }

    internal static bool ReferencesLocal(CilMethodBody body, int index,
        CilLocalVariable local) => LocalAt(body, body.Instructions[index], load: null) is { } found
        && ReferenceEquals(found, local);

    private static bool TryStoredLocal(CilMethodBody body, int index,
        out CilLocalVariable local)
    {
        local = LocalAt(body, body.Instructions[index], load: false)!;
        return local is not null;
    }

    private static CilLocalVariable? LocalAt(CilMethodBody body,
        CilInstruction instruction, bool? load)
    {
        bool Is(bool instructionLoads) => load is null || load == instructionLoads;
        return instruction.OpCode.Code switch
        {
            CilCode.Ldloc or CilCode.Ldloc_S when Is(true) =>
                instruction.Operand as CilLocalVariable,
            CilCode.Ldloc_0 when Is(true) => body.LocalVariables.ElementAtOrDefault(0),
            CilCode.Ldloc_1 when Is(true) => body.LocalVariables.ElementAtOrDefault(1),
            CilCode.Ldloc_2 when Is(true) => body.LocalVariables.ElementAtOrDefault(2),
            CilCode.Ldloc_3 when Is(true) => body.LocalVariables.ElementAtOrDefault(3),
            CilCode.Stloc or CilCode.Stloc_S when Is(false) =>
                instruction.Operand as CilLocalVariable,
            CilCode.Stloc_0 when Is(false) => body.LocalVariables.ElementAtOrDefault(0),
            CilCode.Stloc_1 when Is(false) => body.LocalVariables.ElementAtOrDefault(1),
            CilCode.Stloc_2 when Is(false) => body.LocalVariables.ElementAtOrDefault(2),
            CilCode.Stloc_3 when Is(false) => body.LocalVariables.ElementAtOrDefault(3),
            CilCode.Ldloca or CilCode.Ldloca_S when load is null =>
                instruction.Operand as CilLocalVariable,
            _ => null,
        };
    }

    private static bool TryElement(object? operand, out CilConstantArrayElementKind kind,
        out int size, out CilCode store)
    {
        kind = default;
        size = 0;
        store = default;
        if (operand is not ITypeDescriptor type)
            return false;
        (kind, size, store) = type.FullName switch
        {
            "System.Boolean" => (CilConstantArrayElementKind.Boolean, 1, CilCode.Stelem_I1),
            "System.Byte" => (CilConstantArrayElementKind.Byte, 1, CilCode.Stelem_I1),
            "System.SByte" => (CilConstantArrayElementKind.SByte, 1, CilCode.Stelem_I1),
            "System.Char" => (CilConstantArrayElementKind.Char, 2, CilCode.Stelem_I2),
            "System.Int16" => (CilConstantArrayElementKind.Int16, 2, CilCode.Stelem_I2),
            "System.UInt16" => (CilConstantArrayElementKind.UInt16, 2, CilCode.Stelem_I2),
            "System.Int32" => (CilConstantArrayElementKind.Int32, 4, CilCode.Stelem_I4),
            "System.UInt32" => (CilConstantArrayElementKind.UInt32, 4, CilCode.Stelem_I4),
            "System.Int64" => (CilConstantArrayElementKind.Int64, 8, CilCode.Stelem_I8),
            "System.UInt64" => (CilConstantArrayElementKind.UInt64, 8, CilCode.Stelem_I8),
            "System.Single" => (CilConstantArrayElementKind.Single, 4, CilCode.Stelem_R4),
            "System.Double" => (CilConstantArrayElementKind.Double, 8, CilCode.Stelem_R8),
            _ => default,
        };
        return size != 0;
    }

    private static bool TryConstant(CilInstruction instruction,
        CilConstantArrayElementKind kind, Span<byte> destination)
    {
        if (kind is CilConstantArrayElementKind.Single)
        {
            if (instruction.OpCode.Code != CilCode.Ldc_R4)
                return false;
            BinaryPrimitives.WriteInt32LittleEndian(destination,
                BitConverter.SingleToInt32Bits(Convert.ToSingle(instruction.Operand)));
            return true;
        }
        if (kind is CilConstantArrayElementKind.Double)
        {
            if (instruction.OpCode.Code != CilCode.Ldc_R8)
                return false;
            BinaryPrimitives.WriteInt64LittleEndian(destination,
                BitConverter.DoubleToInt64Bits(Convert.ToDouble(instruction.Operand)));
            return true;
        }
        if (kind is CilConstantArrayElementKind.Int64 or CilConstantArrayElementKind.UInt64)
        {
            if (instruction.OpCode.Code != CilCode.Ldc_I8)
                return false;
            BinaryPrimitives.WriteInt64LittleEndian(destination,
                Convert.ToInt64(instruction.Operand));
            return true;
        }
        if (!TryInt32(instruction, out int value))
            return false;
        switch (destination.Length)
        {
            case 1:
                destination[0] = unchecked((byte)value);
                return true;
            case 2:
                BinaryPrimitives.WriteUInt16LittleEndian(destination, unchecked((ushort)value));
                return true;
            case 4:
                BinaryPrimitives.WriteInt32LittleEndian(destination, value);
                return true;
            default:
                return false;
        }
    }

    private static bool IsArrayCast(CilInstruction instruction,
        CilConstantArrayElementKind kind) => instruction.OpCode.Code == CilCode.Castclass
        && instruction.Operand is ITypeDescriptor type
        && type.FullName == $"System.{kind}[]";

    internal static bool TryInt32(CilInstruction instruction, out int value)
    {
        value = instruction.OpCode.Code switch
        {
            CilCode.Ldc_I4_M1 => -1,
            CilCode.Ldc_I4_0 => 0,
            CilCode.Ldc_I4_1 => 1,
            CilCode.Ldc_I4_2 => 2,
            CilCode.Ldc_I4_3 => 3,
            CilCode.Ldc_I4_4 => 4,
            CilCode.Ldc_I4_5 => 5,
            CilCode.Ldc_I4_6 => 6,
            CilCode.Ldc_I4_7 => 7,
            CilCode.Ldc_I4_8 => 8,
            CilCode.Ldc_I4_S => Convert.ToInt32(instruction.Operand),
            CilCode.Ldc_I4 => Convert.ToInt32(instruction.Operand),
            _ => 0,
        };
        return instruction.OpCode.Code is CilCode.Ldc_I4_M1 or CilCode.Ldc_I4_0
            or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2 or CilCode.Ldc_I4_3
            or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5 or CilCode.Ldc_I4_6
            or CilCode.Ldc_I4_7 or CilCode.Ldc_I4_8 or CilCode.Ldc_I4_S
            or CilCode.Ldc_I4;
    }
}
