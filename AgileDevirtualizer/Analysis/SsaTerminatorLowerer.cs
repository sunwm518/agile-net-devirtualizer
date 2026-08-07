using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Lowers a block terminator for block-ordered emission. The branch to a successor that is laid out
/// immediately next is elided, which keeps the natural fall-through shape of the original code.
/// </summary>
internal static class SsaTerminatorLowerer
{
    public static IReadOnlyList<CilInstruction> Lower(
        BasicBlock block,
        SemanticControlFlowGraph graph,
        IReadOnlyDictionary<int, CilInstructionLabel> labels,
        int? nextBlockId)
    {
        var result = new List<CilInstruction>();
        var normal = SsaControlFlow.Outgoing(graph, block)
            .Where(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)).ToArray();
        switch (block.Terminator.Kind)
        {
            case SemanticTerminatorKind.FallThrough:
            case SemanticTerminatorKind.Branch:
                var successor = normal.SingleOrDefault()
                    ?? throw new InvalidOperationException($"B{block.Id} has no unique successor");
                if (successor.TargetBlockId != nextBlockId)
                    result.Add(new CilInstruction(CilOpCodes.Br,
                        labels[successor.TargetBlockId]));
                break;
            case SemanticTerminatorKind.Conditional:
                var taken = normal.Single(edge =>
                    edge.Kind == ControlFlowEdgeKind.ConditionalTaken);
                var fall = normal.Single(edge =>
                    edge.Kind == ControlFlowEdgeKind.ConditionalFallThrough);
                result.Add(new CilInstruction(SemanticCilLowerer.Lower(
                    block.Terminator, isLeave: false), labels[taken.TargetBlockId]));
                if (fall.TargetBlockId != nextBlockId)
                    result.Add(new CilInstruction(CilOpCodes.Br, labels[fall.TargetBlockId]));
                break;
            case SemanticTerminatorKind.Switch:
                var table = new ICilLabel[block.Terminator.TargetInstructionIndices.Count];
                foreach (var edge in normal.Where(edge =>
                    edge.Kind == ControlFlowEdgeKind.SwitchCase))
                {
                    if (edge.SwitchCaseIndex is not { } caseIndex
                        || caseIndex < 0 || caseIndex >= table.Length)
                        throw new InvalidOperationException($"B{block.Id} has invalid switch case");
                    table[caseIndex] = labels[edge.TargetBlockId];
                }
                if (table.Any(label => label is null))
                    throw new InvalidOperationException($"B{block.Id} has an incomplete switch");
                result.Add(new CilInstruction(CilOpCodes.Switch, table.ToList()));
                var defaultEdge = normal.Single(edge =>
                    edge.Kind == ControlFlowEdgeKind.SwitchDefault);
                if (defaultEdge.TargetBlockId != nextBlockId)
                    result.Add(new CilInstruction(CilOpCodes.Br,
                        labels[defaultEdge.TargetBlockId]));
                break;
            default:
                result.Add(new CilInstruction(SemanticCilLowerer.Lower(
                    block.Terminator, isLeave: false)));
                break;
        }
        return result;
    }
}
