using AgileDevirtualizer.Resource;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Decode;

/// <summary>One decoded VM instruction: its opcode plus the operands its read-method produced.</summary>
internal sealed class VmInstruction
{
    public int Index;
    public ushort Opcode;

    /// <summary>Operand values keyed by the handler field they were stored into (names are stable per build).</summary>
    public Dictionary<string, object?> Operands = new(StringComparer.Ordinal);

    public bool TryGet<T>(string name, out T value)
    {
        if (Operands.TryGetValue(name, out var raw) && raw is T t) { value = t; return true; }
        value = default!;
        return false;
    }

    public override string ToString()
    {
        var ops = string.Join(", ", Operands.Select(kv => $"{kv.Key}={Format(kv.Value)}"));
        return $"[{Index:D3}] op{Opcode}({ops})";
    }

    private static string Format(object? v) => v switch
    {
        null => "null",
        string s => $"\"{s}\"",
        DecodedStringLiteral s => $"\"{s.Value}\"",
        object?[] a => "[" + string.Join(",", a.Select(Format)) + "]",
        _ => v.ToString() ?? "?",
    };
}

/// <summary>A single exception-handling clause, in VM-instruction-index space.</summary>
internal sealed class EhClause
{
    /// <summary>0=catch, 1=filter, 2=finally, 4=fault (mirrors ExceptionHandlingClauseOptions).</summary>
    public int ClauseType;
    public int TryStart;      // inclusive instruction index
    public int TryEnd;        // inclusive instruction index (runtime uses idx <= TryEnd)
    public int HandlerStart;  // instruction index the runtime jumps to
    public int HandlerEnd;    // inclusive instruction index
    public bool HasExtraToken;
    public int ExtraToken;    // catch-type token (catch) / filter info (filter)
}

internal sealed class DecodedMethod
{
    public required VMMethod Source;
    public List<VmInstruction> Instructions = [];
    public List<TypeSignature> Locals = [];
    public List<EhClause> ExceptionHandlers = [];
}
