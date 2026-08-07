using System.Text;
using AgileDevirtualizer.Decode;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

internal sealed record CilAggregateFoldResult(
    int Strings,
    int ByteArrays,
    int CharArrays,
    int RemovedInstructions);

/// <summary>
/// Reconstructs strings from proven constant aggregate values. The array reader is generic over
/// primitive element types, while folding is intentionally limited to exact string-producing BCL
/// consumers. Any alias, non-constant store, branch target or EH-boundary ambiguity rejects the
/// candidate without modifying the method.
/// </summary>
internal static class CilAggregateStringFolder
{
    public static CilAggregateFoldResult Fold(ModuleDefinition module, CilMethodBody body)
    {
        int strings = 0;
        int byteArrays = 0;
        int charArrays = 0;
        int removed = 0;
        for (int start = 0; start + 2 < body.Instructions.Count; start++)
        {
            if (!CilConstantArrayPatternReader.TryRead(body, start, out var array)
                || !TryFindConsumer(body, array, out var consumer)
                || HasOtherLocalUse(body, array, consumer)
                || HasProtectedRange(body, array.AllocationStart, array.InitializationEnd)
                || HasProtectedRange(body, consumer.Start, consumer.End)
                || !SameRegionPath(body, array.AllocationStart, consumer.Start)
                || !OperandDecoder.TryReserveUserString(module, consumer.Text))
                continue;

            int before = body.Instructions.Count;
            ReplaceRange(body.Instructions, consumer.Start, consumer.End,
                [new CilInstruction(CilOpCodes.Ldstr, consumer.Text)]);
            RemoveRange(body.Instructions, array.AllocationStart, array.InitializationEnd);

            strings++;
            if (array.ElementKind == CilConstantArrayElementKind.Byte)
                byteArrays++;
            else
                charArrays++;
            removed += before - body.Instructions.Count;
            start--;
        }
        return new CilAggregateFoldResult(strings, byteArrays, charArrays, removed);
    }

    private static bool TryFindConsumer(CilMethodBody body,
        CilConstantArrayPattern array, out StringConsumer consumer)
    {
        consumer = null!;
        for (int index = array.InitializationEnd + 1;
             index < body.Instructions.Count; index++)
        {
            if (array.ElementKind == CilConstantArrayElementKind.Byte
                && TryEncodingConsumer(body, index, array, out consumer))
                return true;
            if (array.ElementKind == CilConstantArrayElementKind.Char
                && TryCharConsumer(body, index, array, out consumer))
                return true;
        }
        return false;
    }

    private static bool TryEncodingConsumer(CilMethodBody body, int start,
        CilConstantArrayPattern array, out StringConsumer consumer)
    {
        consumer = null!;
        if (!TryStandardEncoding(body.Instructions[start], out var encoding))
            return false;
        int position = start + 1;
        if (position < body.Instructions.Count && IsEncodingCast(body.Instructions[position]))
            position++;
        if (!CilConstantArrayPatternReader.LoadsLocal(body, position, array.Local))
            return false;
        position++;
        if (position < body.Instructions.Count && IsArrayCast(
            body.Instructions[position], "System.Byte[]"))
            position++;
        if (position >= body.Instructions.Count || !IsEncodingGetString(
            body.Instructions[position]))
            return false;

        byte[] bytes = array.Bytes();
        string text;
        try
        {
            text = encoding.GetString(bytes);
            // Reject malformed or fallback-dependent byte sequences. This makes the replacement
            // stable across the target framework and the runtime hosting the devirtualizer.
            if (!encoding.GetBytes(text).SequenceEqual(bytes))
                return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        consumer = new StringConsumer(start, position, text);
        return true;
    }

    private static bool TryCharConsumer(CilMethodBody body, int start,
        CilConstantArrayPattern array, out StringConsumer consumer)
    {
        consumer = null!;
        int position = start;
        if (!CilConstantArrayPatternReader.LoadsLocal(body, position, array.Local))
            return false;
        position++;
        if (position < body.Instructions.Count && IsArrayCast(
            body.Instructions[position], "System.Char[]"))
            position++;
        if (position >= body.Instructions.Count || !IsStringFromChars(
            body.Instructions[position]))
            return false;
        consumer = new StringConsumer(start, position, new string(array.Chars()));
        return true;
    }

    private static bool TryStandardEncoding(CilInstruction instruction, out Encoding encoding)
    {
        encoding = null!;
        if (instruction.OpCode.Code != CilCode.Call
            || instruction.Operand is not IMethodDescriptor method
            || method.DeclaringType?.FullName != "System.Text.Encoding"
            || method.Signature is not { HasThis: false, ParameterTypes.Count: 0 } signature
            || signature.ReturnType.FullName != "System.Text.Encoding")
            return false;
        encoding = method.Name?.ToString() switch
        {
            "get_ASCII" => Encoding.ASCII,
            "get_BigEndianUnicode" => Encoding.BigEndianUnicode,
            "get_Unicode" => Encoding.Unicode,
            "get_UTF8" => Encoding.UTF8,
            "get_UTF32" => Encoding.UTF32,
            _ => null!,
        };
        return encoding is not null;
    }

    private static bool IsEncodingGetString(CilInstruction instruction) =>
        instruction.OpCode.Code == CilCode.Callvirt
        && instruction.Operand is IMethodDescriptor method
        && method.DeclaringType?.FullName == "System.Text.Encoding"
        && method.Name?.ToString() == "GetString"
        && method.Signature is { HasThis: true, ParameterTypes.Count: 1 } signature
        && signature.ParameterTypes[0].FullName == "System.Byte[]"
        && signature.ReturnType.FullName == "System.String";

    private static bool IsStringFromChars(CilInstruction instruction) =>
        instruction.OpCode.Code == CilCode.Newobj
        && instruction.Operand is IMethodDescriptor method
        && method.DeclaringType?.FullName == "System.String"
        && method.Name?.ToString() == ".ctor"
        && method.Signature is { HasThis: true, ParameterTypes.Count: 1 } signature
        && signature.ParameterTypes[0].FullName == "System.Char[]";

    private static bool IsEncodingCast(CilInstruction instruction) =>
        instruction.OpCode.Code == CilCode.Castclass
        && instruction.Operand is ITypeDescriptor type
        && type.FullName == "System.Text.Encoding";

    private static bool IsArrayCast(CilInstruction instruction, string name) =>
        instruction.OpCode.Code == CilCode.Castclass
        && instruction.Operand is ITypeDescriptor type
        && type.FullName == name;

    private static bool HasOtherLocalUse(CilMethodBody body,
        CilConstantArrayPattern array, StringConsumer consumer)
    {
        for (int index = 0; index < body.Instructions.Count; index++)
        {
            if (!CilConstantArrayPatternReader.ReferencesLocal(body, index, array.Local))
                continue;
            if (index == array.AllocationStore
                || array.InitializationInstructions.Contains(index)
                || index >= consumer.Start && index <= consumer.End)
                continue;
            return true;
        }
        return false;
    }

    private static bool HasProtectedRange(CilMethodBody body, int start, int end)
    {
        var removed = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
        for (int index = start; index <= end; index++)
            removed.Add(body.Instructions[index]);
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is CilInstructionLabel { Instruction: { } target }
                && removed.Contains(target))
                return true;
            if (instruction.Operand is IList<ICilLabel> labels
                && labels.Any(label => label is CilInstructionLabel { Instruction: { } target }
                    && removed.Contains(target)))
                return true;
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            if (IsBoundary(handler.TryStart) || IsBoundary(handler.TryEnd)
                || IsBoundary(handler.HandlerStart) || IsBoundary(handler.HandlerEnd)
                || IsBoundary(handler.FilterStart))
                return true;
        }
        return false;

        bool IsBoundary(ICilLabel? label) => label is CilInstructionLabel
            { Instruction: { } instruction } && removed.Contains(instruction);
    }

    private static bool SameRegionPath(CilMethodBody body, int left, int right)
    {
        var positions = new Dictionary<CilInstruction, int>(ReferenceEqualityComparer.Instance);
        for (int index = 0; index < body.Instructions.Count; index++)
            positions[body.Instructions[index]] = index;
        return RegionPath(left).SequenceEqual(RegionPath(right));

        IEnumerable<string> RegionPath(int index)
        {
            for (int handlerIndex = 0; handlerIndex < body.ExceptionHandlers.Count; handlerIndex++)
            {
                var handler = body.ExceptionHandlers[handlerIndex];
                if (Contains(handler.TryStart, handler.TryEnd, index))
                    yield return $"T{handlerIndex}";
                if (Contains(handler.FilterStart, handler.HandlerStart, index))
                    yield return $"F{handlerIndex}";
                if (Contains(handler.HandlerStart, handler.HandlerEnd, index))
                    yield return $"H{handlerIndex}";
            }
        }

        bool Contains(ICilLabel? startLabel, ICilLabel? endLabel, int index)
        {
            if (startLabel is not CilInstructionLabel { Instruction: { } startInstruction }
                || !positions.TryGetValue(startInstruction, out int startIndex))
                return false;
            int endIndex = body.Instructions.Count;
            if (endLabel is CilInstructionLabel { Instruction: { } endInstruction }
                && positions.TryGetValue(endInstruction, out int foundEnd))
                endIndex = foundEnd;
            return index >= startIndex && index < endIndex;
        }
    }

    private static void ReplaceRange(CilInstructionCollection instructions,
        int start, int end, IReadOnlyList<CilInstruction> replacements)
    {
        for (int index = end; index >= start; index--)
            instructions.RemoveAt(index);
        for (int index = 0; index < replacements.Count; index++)
            instructions.Insert(start + index, replacements[index]);
    }

    private static void RemoveRange(CilInstructionCollection instructions, int start, int end)
    {
        for (int index = end; index >= start; index--)
            instructions.RemoveAt(index);
    }

    private sealed record StringConsumer(int Start, int End, string Text);
}
