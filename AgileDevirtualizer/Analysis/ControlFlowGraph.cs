namespace AgileDevirtualizer.Analysis;

internal enum SemanticTerminatorKind
{
    FallThrough,
    Branch,
    Conditional,
    Switch,
    Return,
    Throw,
    Rethrow,
    EndFinally,
    EndFilter,
}

internal sealed record SemanticTerminator(
    SemanticTerminatorKind Kind,
    IReadOnlyList<int> TargetInstructionIndices,
    string LegacyDisplay,
    SemanticTerminatorSemantics Semantics = default);

internal enum ControlFlowEdgeKind
{
    FallThrough,
    Branch,
    Leave,
    ConditionalTaken,
    ConditionalFallThrough,
    SwitchCase,
    SwitchDefault,
    ExceptionCatch,
    ExceptionFilter,
    ExceptionFilterHandler,
    ExceptionFinally,
    ExceptionFault,
}

internal sealed record BasicBlock(
    int Id,
    int StartInstructionIndex,
    int EndInstructionIndex,
    RegionPath RegionPath,
    IReadOnlyList<SemanticOperation> Operations,
    SemanticTerminator Terminator);

internal sealed record ControlFlowEdge(
    int SourceBlockId,
    int TargetBlockId,
    ControlFlowEdgeKind Kind,
    int? SwitchCaseIndex = null,
    int? ExceptionRegionId = null);

internal sealed class SemanticControlFlowGraph
{
    private readonly Dictionary<int, BasicBlock> _blockByInstruction;

    public SemanticControlFlowGraph(
        int instructionCount,
        IReadOnlyList<BasicBlock> blocks,
        IReadOnlyList<ControlFlowEdge> edges,
        IReadOnlyList<ExceptionRegion> exceptionRegions)
    {
        InstructionCount = instructionCount;
        Blocks = blocks;
        Edges = edges;
        ExceptionRegions = exceptionRegions;
        _blockByInstruction = new Dictionary<int, BasicBlock>();
        foreach (var block in blocks)
            for (int index = block.StartInstructionIndex; index <= block.EndInstructionIndex; index++)
                _blockByInstruction[index] = block;
    }

    public int InstructionCount { get; }
    public IReadOnlyList<BasicBlock> Blocks { get; }
    public IReadOnlyList<ControlFlowEdge> Edges { get; }
    public IReadOnlyList<ExceptionRegion> ExceptionRegions { get; }

    public BasicBlock BlockContaining(int instructionIndex) => _blockByInstruction[instructionIndex];

    public IEnumerable<ControlFlowEdge> Incoming(BasicBlock block) =>
        Edges.Where(edge => edge.TargetBlockId == block.Id);

    public IEnumerable<ControlFlowEdge> Outgoing(BasicBlock block) =>
        Edges.Where(edge => edge.SourceBlockId == block.Id);
}
