namespace AgileDevirtualizer.Analysis;

internal sealed record DispatcherStateSlice(
    int PredecessorBlockId,
    int StoreInstructionId,
    IReadOnlySet<int> RemovableInstructionIds);

internal sealed record DispatcherElimination(
    DispatcherPlan Dispatcher,
    IReadOnlyList<DispatcherStateSlice> StateSlices);

internal sealed class DispatcherEliminationResult
{
    public DispatcherEliminationResult(
        ControlFlowSimplificationResult simplification,
        IReadOnlyList<DispatcherElimination> eliminations,
        IReadOnlyList<string> rejections)
    {
        Simplification = simplification;
        Eliminations = eliminations;
        Rejections = rejections;
    }

    public ControlFlowSimplificationResult Simplification { get; }
    public IReadOnlyList<DispatcherElimination> Eliminations { get; }
    public IReadOnlyList<string> Rejections { get; }
}

internal static class DispatcherEliminationPlanner
{
    public static DispatcherEliminationResult Analyze(
        ControlFlowSimplificationResult simplification)
    {
        var eliminations = new List<DispatcherElimination>();
        var rejections = new List<string>();
        foreach (var dispatcher in simplification.Dispatchers)
        {
            if (TryPlan(dispatcher, simplification, out var elimination, out string reason))
                eliminations.Add(elimination);
            else
                rejections.Add($"B{dispatcher.BlockId}: {reason}");
        }
        return new DispatcherEliminationResult(simplification, eliminations, rejections);
    }

    private static bool TryPlan(
        DispatcherPlan dispatcher,
        ControlFlowSimplificationResult simplification,
        out DispatcherElimination elimination,
        out string reason)
    {
        elimination = null!;
        reason = string.Empty;
        var graph = simplification.DeadCode.Sccp.Graph;
        var sourceGraph = graph.Source;
        var dispatchBlock = graph.Blocks[dispatcher.BlockId];
        var normalIncoming = SsaControlFlow.Incoming(sourceGraph,
                sourceGraph.Blocks[dispatcher.BlockId])
            .Where(simplification.RetainedEdges.Contains)
            .Where(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)).ToArray();
        if (normalIncoming.Length != dispatcher.Transitions.Count)
        {
            reason = "finite states do not cover every executable incoming edge";
            return false;
        }

        var slices = new List<DispatcherStateSlice>();
        foreach (var transition in dispatcher.Transitions)
        {
            var predecessor = graph.Blocks[transition.PredecessorBlockId];
            var normalOutgoing = ControlFlowSimplifier.NormalOutgoing(
                    sourceGraph, predecessor.Id)
                .Where(simplification.RetainedEdges.Contains).ToArray();
            if (normalOutgoing.Length != 1 || normalOutgoing[0] != transition.IncomingEdge
                || predecessor.Terminator?.Terminator.Kind is not
                    SemanticTerminatorKind.Branch and not SemanticTerminatorKind.FallThrough)
            {
                reason = $"B{predecessor.Id} does not enter the dispatcher unconditionally";
                return false;
            }
            if (!ControlFlowSimplifier.SameRegion(
                    sourceGraph.Blocks[predecessor.Id].RegionPath,
                    sourceGraph.Blocks[dispatcher.BlockId].RegionPath)
                || !ControlFlowSimplifier.SameRegion(
                    sourceGraph.Blocks[dispatcher.BlockId].RegionPath,
                    sourceGraph.Blocks[transition.SelectedEdge.TargetBlockId].RegionPath))
            {
                reason = $"B{predecessor.Id} transition crosses an exception-region boundary";
                return false;
            }
            if (!TryStateSlice(predecessor, dispatchBlock, dispatcher.SelectorValueId,
                transition.StateValueId, simplification.DeadCode.Sccp,
                out var slice, out reason))
            {
                reason = $"B{predecessor.Id}: {reason}";
                return false;
            }
            slices.Add(slice);
        }

        elimination = new DispatcherElimination(dispatcher, slices);
        return true;
    }

    private static bool TryStateSlice(
        SsaBlock predecessor,
        SsaBlock dispatcher,
        int selectorValueId,
        int stateValueId,
        SccpResult sccp,
        out DispatcherStateSlice slice,
        out string reason)
    {
        slice = null!;
        reason = string.Empty;
        var selector = dispatcher.Phis.Single(phi => phi.Result.Id == selectorValueId);
        if (selector.Variable is not { } variable)
        {
            reason = "switch selector is not a variable phi";
            return false;
        }
        var stores = predecessor.Instructions.Where(instruction =>
            instruction.Inputs.Count == 1 && instruction.Inputs[0] == stateValueId
            && IsStoreOf(instruction.Operation, variable)).ToArray();
        if (stores.Length != 1)
        {
            reason = $"expected one selector store, found {stores.Length}";
            return false;
        }

        var byOutput = predecessor.Instructions
            .SelectMany(instruction => instruction.Outputs.Select(output => (output, instruction)))
            .ToDictionary(pair => pair.output, pair => pair.instruction);
        var removable = new HashSet<int> { stores[0].Id };
        var values = new Stack<int>();
        values.Push(stateValueId);
        while (values.Count > 0)
        {
            int valueId = values.Pop();
            if (!byOutput.TryGetValue(valueId, out var definition)
                || !SemanticEffectClassifier.CanReplaceWithConstant(definition)
                || sccp.Values[valueId].Kind != SccpValueKind.Constant)
            {
                reason = $"%{valueId} is not a local pure constant definition";
                return false;
            }
            if (!removable.Add(definition.Id))
                continue;
            foreach (int input in definition.Inputs)
                values.Push(input);
            AddPrefixes(definition, predecessor, removable);
        }

        int first = removable.Select(id => predecessor.Instructions
            .Single(instruction => instruction.Id == id).Ordinal).Min();
        var suffix = predecessor.Instructions.Skip(first).Select(instruction => instruction.Id)
            .ToHashSet();
        if (!suffix.SetEquals(removable))
        {
            reason = "state calculation is not an isolated instruction suffix";
            return false;
        }
        if (!OutputsArePrivate(removable, predecessor, dispatcher, selectorValueId, sccp.Graph))
        {
            reason = "state calculation has a non-dispatcher use";
            return false;
        }

        slice = new DispatcherStateSlice(predecessor.Id, stores[0].Id, removable);
        return true;
    }

    private static bool OutputsArePrivate(
        IReadOnlySet<int> removable,
        SsaBlock predecessor,
        SsaBlock dispatcher,
        int selectorValueId,
        SsaGraph graph)
    {
        var outputs = predecessor.Instructions.Where(instruction => removable.Contains(instruction.Id))
            .SelectMany(instruction => instruction.Outputs).ToHashSet();
        foreach (var use in graph.Uses.Where(use => outputs.Contains(use.ValueId)))
        {
            if (use.Kind == SsaUseKind.InstructionInput)
            {
                var consumer = graph.Blocks[use.BlockId].Instructions
                    .Single(instruction => instruction.Ordinal == use.InstructionOrdinal);
                if (!removable.Contains(consumer.Id))
                    return false;
                continue;
            }
            if (use.Kind == SsaUseKind.PhiInput && use.BlockId == dispatcher.Id
                && dispatcher.Phis.Single(phi => phi.Result.Id == selectorValueId)
                    .Inputs.Any(input => input.ValueId == use.ValueId))
                continue;
            return false;
        }
        return true;
    }

    private static void AddPrefixes(
        SsaInstruction instruction,
        SsaBlock block,
        ISet<int> removable)
    {
        for (int ordinal = instruction.Ordinal - 1; ordinal >= 0; ordinal--)
        {
            var prefix = block.Instructions[ordinal];
            if (prefix.Operation.Code != SemanticOperationCode.Prefix)
                break;
            removable.Add(prefix.Id);
        }
    }

    private static bool IsStoreOf(
        SemanticOperation operation,
        SsaVariableSlot variable) => (operation.Code, operation.Operand) switch
    {
        (SemanticOperationCode.StoreLocal, SemanticLocalReference local) =>
            variable == new SsaVariableSlot(SsaVariableKind.Local, local.Index, local.Temporary),
        (SemanticOperationCode.StoreArgument, SemanticArgumentReference argument) =>
            variable == new SsaVariableSlot(SsaVariableKind.Argument, argument.Index),
        _ => false,
    };
}
