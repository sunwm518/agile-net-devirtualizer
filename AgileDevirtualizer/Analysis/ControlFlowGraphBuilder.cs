using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Builds an observational semantic CFG from decoded VM indices and the green legacy lift. The
/// result is never consulted by method acceptance or CIL emission.
/// </summary>
internal static class ControlFlowGraphBuilder
{
    public static SemanticControlFlowGraph Build(
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted)
    {
        int instructionCount = decoded.Instructions.Count;
        var regions = BuildRegions(decoded.ExceptionHandlers);
        if (instructionCount == 0)
            return new SemanticControlFlowGraph(0, Array.Empty<BasicBlock>(),
                Array.Empty<ControlFlowEdge>(), regions);

        var leaders = FindLeaders(decoded, lifted, instructionCount);
        int[] starts = leaders.ToArray();
        var blocks = new List<BasicBlock>(starts.Length);
        for (int id = 0; id < starts.Length; id++)
        {
            int start = starts[id];
            int end = (id + 1 < starts.Length ? starts[id + 1] : instructionCount) - 1;
            blocks.Add(new BasicBlock(id, start, end, RegionPathAt(regions, start),
                BuildOperations(lifted, start, end), BuildTerminator(lifted, end, instructionCount)));
        }

        var blockByInstruction = new int[instructionCount];
        foreach (var block in blocks)
            for (int index = block.StartInstructionIndex; index <= block.EndInstructionIndex; index++)
                blockByInstruction[index] = block.Id;

        var edges = BuildNormalEdges(blocks, lifted, blockByInstruction, instructionCount);
        AddExceptionEdges(edges, blocks, regions, blockByInstruction);
        return new SemanticControlFlowGraph(instructionCount, blocks, edges, regions);
    }

    internal static RegionPath RegionPathAt(
        IReadOnlyList<ExceptionRegion> regions,
        int instructionIndex)
    {
        var frames = new List<(RegionFrame Frame, int Span)>();
        foreach (var region in regions)
        {
            int span = region.FullEnd - region.FullStart;
            if (instructionIndex >= region.TryStart && instructionIndex <= region.TryEnd)
                frames.Add((new RegionFrame(region.Id, region.ClauseKind, RegionZone.Try), span));
            if (region.FilterStart is { } filterStart
                && instructionIndex >= filterStart && instructionIndex < region.HandlerStart)
                frames.Add((new RegionFrame(region.Id, region.ClauseKind, RegionZone.Filter), span));
            if (instructionIndex >= region.HandlerStart && instructionIndex <= region.HandlerEnd)
                frames.Add((new RegionFrame(region.Id, region.ClauseKind, RegionZone.Handler), span));
        }

        if (frames.Count == 0)
            return RegionPath.Outside;
        return new RegionPath(frames
            .OrderByDescending(item => item.Span)
            .ThenBy(item => item.Frame.RegionId)
            .ThenBy(item => item.Frame.Zone)
            .Select(item => item.Frame)
            .ToArray());
    }

    private static IReadOnlyList<ExceptionRegion> BuildRegions(IReadOnlyList<EhClause> handlers) =>
        handlers.Select((handler, id) => new ExceptionRegion(
            id,
            ClauseKind(handler.ClauseType),
            handler.TryStart,
            handler.TryEnd,
            handler.HandlerStart,
            handler.HandlerEnd,
            handler.ClauseType == 0 && handler.HasExtraToken ? handler.ExtraToken : null,
            handler.ClauseType == 1 && handler.HasExtraToken ? handler.ExtraToken : null)).ToArray();

    private static SortedSet<int> FindLeaders(
        DecodedMethod decoded,
        IReadOnlyList<List<LiftedOp>> lifted,
        int instructionCount)
    {
        var leaders = new SortedSet<int> { 0 };
        foreach (var handler in decoded.ExceptionHandlers)
        {
            AddLeader(leaders, handler.TryStart, instructionCount);
            AddLeader(leaders, handler.TryEnd + 1, instructionCount);
            AddLeader(leaders, handler.HandlerStart, instructionCount);
            AddLeader(leaders, handler.HandlerEnd + 1, instructionCount);
            if (handler.ClauseType == 1 && handler.HasExtraToken)
                AddLeader(leaders, handler.ExtraToken, instructionCount);
        }

        for (int index = 0; index < lifted.Count; index++)
        {
            foreach (var operation in lifted[index])
            {
                if (operation.Operand is VmTarget target)
                    AddLeader(leaders, target.Index, instructionCount);
                else if (operation.Operand is VmTarget[] targets)
                    foreach (var item in targets)
                        AddLeader(leaders, item.Index, instructionCount);
                if (IsTerminator(operation.OpCode.Code))
                    AddLeader(leaders, index + 1, instructionCount);
            }
        }
        return leaders;
    }

    private static IReadOnlyList<SemanticOperation> BuildOperations(
        IReadOnlyList<List<LiftedOp>> lifted,
        int start,
        int end)
    {
        var operations = new List<SemanticOperation>();
        for (int index = start; index <= end && index < lifted.Count; index++)
        {
            for (int operationIndex = 0; operationIndex < lifted[index].Count; operationIndex++)
            {
                var operation = lifted[index][operationIndex];
                bool finalTerminator = index == end
                    && operationIndex == lifted[index].Count - 1
                    && IsTerminator(operation.OpCode.Code);
                if (!finalTerminator)
                    operations.Add(LegacySemanticIrAdapter.Convert(index, operation));
            }
        }
        return operations;
    }

    private static SemanticTerminator BuildTerminator(
        IReadOnlyList<List<LiftedOp>> lifted,
        int sourceInstructionIndex,
        int instructionCount)
    {
        LiftedOp? operation = sourceInstructionIndex < lifted.Count
            ? lifted[sourceInstructionIndex].LastOrDefault()
            : null;
        if (operation is null || !IsTerminator(operation.OpCode.Code))
        {
            int[] targets = sourceInstructionIndex + 1 < instructionCount
                ? [sourceInstructionIndex + 1]
                : [];
            return new SemanticTerminator(SemanticTerminatorKind.FallThrough, targets, "fallthrough");
        }

        int[] ExplicitTargets() => operation.Operand switch
        {
            VmTarget target => [target.Index],
            VmTarget[] targets => targets.Select(target => target.Index).ToArray(),
            _ => [],
        };

        var kind = operation.OpCode.Code switch
        {
            CilCode.Br or CilCode.Br_S or CilCode.Leave or CilCode.Leave_S =>
                SemanticTerminatorKind.Branch,
            CilCode.Switch => SemanticTerminatorKind.Switch,
            CilCode.Ret => SemanticTerminatorKind.Return,
            CilCode.Throw => SemanticTerminatorKind.Throw,
            CilCode.Rethrow => SemanticTerminatorKind.Rethrow,
            CilCode.Endfinally => SemanticTerminatorKind.EndFinally,
            CilCode.Endfilter => SemanticTerminatorKind.EndFilter,
            _ when IsConditional(operation.OpCode.Code) => SemanticTerminatorKind.Conditional,
            _ => SemanticTerminatorKind.FallThrough,
        };
        return new SemanticTerminator(kind, ExplicitTargets(), operation.ToString(),
            SemanticInstructionSemanticsAdapter.ForTerminator(operation.OpCode.Code));
    }

    private static List<ControlFlowEdge> BuildNormalEdges(
        IReadOnlyList<BasicBlock> blocks,
        IReadOnlyList<List<LiftedOp>> lifted,
        int[] blockByInstruction,
        int instructionCount)
    {
        var edges = new List<ControlFlowEdge>();
        foreach (var block in blocks)
        {
            int sourceIndex = block.EndInstructionIndex;
            LiftedOp? operation = sourceIndex < lifted.Count ? lifted[sourceIndex].LastOrDefault() : null;
            int fallThroughIndex = sourceIndex + 1;

            if (operation?.OpCode.Code == CilCode.Switch && operation.Operand is VmTarget[] cases)
            {
                for (int caseIndex = 0; caseIndex < cases.Length; caseIndex++)
                    AddNormalEdge(edges, block, cases[caseIndex].Index, ControlFlowEdgeKind.SwitchCase,
                        blockByInstruction, instructionCount, caseIndex);
                AddNormalEdge(edges, block, fallThroughIndex, ControlFlowEdgeKind.SwitchDefault,
                    blockByInstruction, instructionCount);
            }
            else if (operation?.Operand is VmTarget target && IsConditional(operation.OpCode.Code))
            {
                AddNormalEdge(edges, block, target.Index, ControlFlowEdgeKind.ConditionalTaken,
                    blockByInstruction, instructionCount);
                AddNormalEdge(edges, block, fallThroughIndex,
                    ControlFlowEdgeKind.ConditionalFallThrough, blockByInstruction, instructionCount);
            }
            else if (operation?.Operand is VmTarget branchTarget
                && operation.OpCode.Code is CilCode.Br or CilCode.Br_S or CilCode.Leave or CilCode.Leave_S)
            {
                var targetPath = RegionPathAtForTarget(blocks, blockByInstruction, branchTarget.Index);
                var kind = operation.OpCode.Code is CilCode.Leave or CilCode.Leave_S
                    || block.RegionPath.ExitsTo(targetPath)
                    ? ControlFlowEdgeKind.Leave
                    : ControlFlowEdgeKind.Branch;
                AddNormalEdge(edges, block, branchTarget.Index, kind,
                    blockByInstruction, instructionCount);
            }
            else if (operation is null || !IsTerminalWithoutTarget(operation.OpCode.Code))
            {
                var targetPath = fallThroughIndex < instructionCount
                    ? RegionPathAtForTarget(blocks, blockByInstruction, fallThroughIndex)
                    : RegionPath.Outside;
                var kind = block.RegionPath.ExitsTo(targetPath)
                    ? ControlFlowEdgeKind.Leave : ControlFlowEdgeKind.FallThrough;
                AddNormalEdge(edges, block, fallThroughIndex, kind,
                    blockByInstruction, instructionCount);
            }
        }
        return edges;
    }

    private static void AddExceptionEdges(
        List<ControlFlowEdge> edges,
        IReadOnlyList<BasicBlock> blocks,
        IReadOnlyList<ExceptionRegion> regions,
        int[] blockByInstruction)
    {
        foreach (var region in regions)
        {
            int targetBlock = blockByInstruction[region.ExceptionDispatchStart];
            var kind = region.ClauseKind switch
            {
                ExceptionClauseKind.Catch => ControlFlowEdgeKind.ExceptionCatch,
                ExceptionClauseKind.Filter => ControlFlowEdgeKind.ExceptionFilter,
                ExceptionClauseKind.Finally => ControlFlowEdgeKind.ExceptionFinally,
                ExceptionClauseKind.Fault => ControlFlowEdgeKind.ExceptionFault,
                _ => ControlFlowEdgeKind.ExceptionCatch,
            };
            foreach (var block in blocks.Where(block =>
                block.StartInstructionIndex >= region.TryStart
                && block.StartInstructionIndex <= region.TryEnd))
            {
                edges.Add(new ControlFlowEdge(block.Id, targetBlock, kind,
                    ExceptionRegionId: region.Id));
            }

            if (region is { ClauseKind: ExceptionClauseKind.Filter, FilterStart: not null })
            {
                int handlerBlock = blockByInstruction[region.HandlerStart];
                foreach (var block in blocks.Where(block =>
                    block.RegionPath.Frames.Any(frame => frame.RegionId == region.Id
                        && frame.Zone == RegionZone.Filter)
                    && block.Terminator.Kind == SemanticTerminatorKind.EndFilter))
                {
                    edges.Add(new ControlFlowEdge(block.Id, handlerBlock,
                        ControlFlowEdgeKind.ExceptionFilterHandler,
                        ExceptionRegionId: region.Id));
                }
            }
        }
    }

    private static RegionPath RegionPathAtForTarget(
        IReadOnlyList<BasicBlock> blocks,
        int[] blockByInstruction,
        int instructionIndex) => blocks[blockByInstruction[instructionIndex]].RegionPath;

    private static void AddNormalEdge(
        List<ControlFlowEdge> edges,
        BasicBlock source,
        int targetInstructionIndex,
        ControlFlowEdgeKind kind,
        int[] blockByInstruction,
        int instructionCount,
        int? switchCaseIndex = null)
    {
        if (targetInstructionIndex < 0 || targetInstructionIndex >= instructionCount)
            return;
        edges.Add(new ControlFlowEdge(source.Id, blockByInstruction[targetInstructionIndex], kind,
            SwitchCaseIndex: switchCaseIndex));
    }

    private static void AddLeader(SortedSet<int> leaders, int index, int instructionCount)
    {
        if (index >= 0 && index < instructionCount)
            leaders.Add(index);
    }

    private static ExceptionClauseKind ClauseKind(int clauseType) => clauseType switch
    {
        0 => ExceptionClauseKind.Catch,
        1 => ExceptionClauseKind.Filter,
        2 => ExceptionClauseKind.Finally,
        4 => ExceptionClauseKind.Fault,
        _ => ExceptionClauseKind.Unknown,
    };

    private static bool IsConditional(CilCode code) => code is
        CilCode.Brtrue or CilCode.Brtrue_S or CilCode.Brfalse or CilCode.Brfalse_S or
        CilCode.Beq or CilCode.Beq_S or CilCode.Bne_Un or CilCode.Bne_Un_S or
        CilCode.Blt or CilCode.Blt_S or CilCode.Blt_Un or CilCode.Blt_Un_S or
        CilCode.Bgt or CilCode.Bgt_S or CilCode.Bgt_Un or CilCode.Bgt_Un_S or
        CilCode.Ble or CilCode.Ble_S or CilCode.Ble_Un or CilCode.Ble_Un_S or
        CilCode.Bge or CilCode.Bge_S or CilCode.Bge_Un or CilCode.Bge_Un_S;

    private static bool IsTerminator(CilCode code) =>
        code is CilCode.Br or CilCode.Br_S or CilCode.Leave or CilCode.Leave_S or CilCode.Switch
        || IsConditional(code) || IsTerminalWithoutTarget(code);

    private static bool IsTerminalWithoutTarget(CilCode code) => code is
        CilCode.Ret or CilCode.Throw or CilCode.Rethrow or CilCode.Endfinally or CilCode.Endfilter;
}
