using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// A branch/switch target expressed as a VM-instruction index (the granularity Agile branches at).
/// The emitter turns these into real CIL labels once every VM instruction has a start label.
/// </summary>
internal readonly record struct VmTarget(int Index)
{
    public override string ToString() => $"→#{Index}";
}

/// <summary>
/// One recovered CIL instruction: an opcode plus a neutral operand (constant, resolved metadata
/// member, local/arg index, or a <see cref="VmTarget"/>). Kept independent of AsmResolver's
/// CilInstruction so lifting is testable on its own; the emitter (M4) lowers these to real CIL.
/// </summary>
internal sealed record LiftedOp(CilOpCode OpCode, object? Operand = null)
{
    public override string ToString() =>
        Operand is null ? OpCode.Mnemonic : $"{OpCode.Mnemonic} {Format(Operand)}";

    private static string Format(object? o) => o switch
    {
        null => "",
        string s => $"\"{s}\"",
        VmTarget t => t.ToString(),
        _ => o.ToString() ?? "?",
    };
}
