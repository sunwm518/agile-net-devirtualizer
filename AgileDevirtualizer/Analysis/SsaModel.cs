namespace AgileDevirtualizer.Analysis;

internal enum SsaValueKind
{
    InitialLocal,
    InitialArgument,
    Phi,
    Operation,
    ExceptionObject,
}

internal enum SsaVariableKind
{
    Local,
    Argument,
}

internal readonly record struct SsaVariableSlot(
    SsaVariableKind Kind,
    int Index,
    bool Temporary = false)
{
    public override string ToString() => Kind == SsaVariableKind.Argument
        ? $"a{Index}"
        : $"{(Temporary ? "t" : "v")}{Index}";
}

internal sealed record SsaValue(
    int Id,
    SsaValueKind Kind,
    AbstractValue AbstractValue,
    int? DefinitionBlockId = null,
    int? DefinitionInstructionOrdinal = null,
    SsaVariableSlot? Variable = null,
    int? StackSlot = null)
{
    public override string ToString() => $"%{Id}:{AbstractValue}";
}

internal enum SsaPhiLocationKind
{
    Variable,
    EvaluationStack,
}

internal enum SsaPhiInputKind
{
    Predecessor,
    MethodEntry,
}

internal sealed record SsaPhiInput(
    SsaPhiInputKind Kind,
    int? PredecessorBlockId,
    int ValueId,
    ControlFlowEdgeKind? EdgeKind = null);

internal sealed record SsaPhi(
    SsaValue Result,
    SsaPhiLocationKind LocationKind,
    SsaVariableSlot? Variable,
    int? StackSlot,
    IReadOnlyList<SsaPhiInput> Inputs);

internal sealed record SsaInstruction(
    int Id,
    int BlockId,
    int Ordinal,
    SemanticOperation Operation,
    IReadOnlyList<int> Inputs,
    IReadOnlyList<int> Outputs);

internal sealed record SsaTerminator(
    SemanticTerminator Terminator,
    IReadOnlyList<int> Inputs);

internal sealed record SsaBlock(
    int Id,
    bool Reachable,
    IReadOnlyList<SsaPhi> Phis,
    IReadOnlyList<SsaInstruction> Instructions,
    SsaTerminator? Terminator,
    IReadOnlyList<int> EntryStack,
    IReadOnlyList<int> ExitStack,
    IReadOnlyDictionary<SsaVariableSlot, int> EntryVariables,
    IReadOnlyDictionary<SsaVariableSlot, int> ExitVariables);

internal enum SsaUseKind
{
    PhiInput,
    InstructionInput,
    TerminatorInput,
}

internal sealed record SsaUse(
    int ValueId,
    SsaUseKind Kind,
    int BlockId,
    int? InstructionOrdinal = null,
    int? PredecessorBlockId = null);

internal sealed class SsaGraph
{
    private readonly Dictionary<int, SsaValue> _valueById;

    public SsaGraph(
        SemanticControlFlowGraph source,
        IReadOnlyList<SsaBlock> blocks,
        IReadOnlyList<SsaValue> values,
        IReadOnlyList<SsaUse> uses,
        IReadOnlyList<SsaVariableSlot> variables)
    {
        Source = source;
        Blocks = blocks;
        Values = values;
        Uses = uses;
        Variables = variables;
        _valueById = values.ToDictionary(value => value.Id);
    }

    public SemanticControlFlowGraph Source { get; }
    public IReadOnlyList<SsaBlock> Blocks { get; }
    public IReadOnlyList<SsaValue> Values { get; }
    public IReadOnlyList<SsaUse> Uses { get; }
    public IReadOnlyList<SsaVariableSlot> Variables { get; }

    public SsaValue Value(int id) => _valueById[id];
}
