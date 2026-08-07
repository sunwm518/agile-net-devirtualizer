namespace AgileDevirtualizer.Analysis;

internal sealed record SsaVerificationResult(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal sealed record SsaStatistics(
    int ReachableBlocks,
    int UnreachableBlocks,
    int Values,
    int Phis,
    int Instructions,
    int Uses);

/// <summary>Checks structural, def-use, phi, stack-shape and dominance invariants.</summary>
internal static class SsaVerifier
{
    public static SsaVerificationResult Verify(
        SsaGraph graph,
        WorklistAnalysisResult analysis)
    {
        var errors = new List<string>();
        if (!ReferenceEquals(graph.Source, analysis.Graph))
            errors.Add("SSA graph and worklist refer to different CFG instances");
        if (graph.Blocks.Count != graph.Source.Blocks.Count)
            errors.Add("SSA block count differs from source CFG");

        var values = graph.Values.GroupBy(value => value.Id).ToArray();
        foreach (var duplicate in values.Where(group => group.Count() != 1))
            errors.Add($"SSA value %{duplicate.Key} has {duplicate.Count()} definitions");
        var valueById = values.Where(group => group.Count() == 1)
            .ToDictionary(group => group.Key, group => group.Single());
        var instructionIds = graph.Blocks.SelectMany(block => block.Instructions)
            .GroupBy(instruction => instruction.Id);
        foreach (var duplicate in instructionIds.Where(group => group.Count() != 1))
            errors.Add($"SSA instruction {duplicate.Key} occurs {duplicate.Count()} times");

        foreach (var block in graph.Blocks)
        {
            if (block.Id < 0 || block.Id >= graph.Source.Blocks.Count)
            {
                errors.Add($"invalid SSA block id {block.Id}");
                continue;
            }
            bool expectedReachable = analysis.Blocks[block.Id].Entry.Reachable;
            if (block.Reachable != expectedReachable)
                errors.Add($"B{block.Id} reachability disagrees with worklist");
            if (!block.Reachable)
            {
                if (block.Phis.Count != 0 || block.Instructions.Count != 0
                    || block.Terminator is not null)
                    errors.Add($"unreachable B{block.Id} contains SSA instructions");
                continue;
            }

            if (block.Terminator is null)
                errors.Add($"reachable B{block.Id} has no SSA terminator");
            if (!block.Instructions.Select(instruction => instruction.Ordinal)
                .SequenceEqual(Enumerable.Range(0, block.Instructions.Count)))
                errors.Add($"B{block.Id} instruction ordinals are not contiguous");
            if (block.Instructions.Count != graph.Source.Blocks[block.Id].Operations.Count)
                errors.Add($"B{block.Id} operation count changed during SSA conversion");
            if (analysis.Blocks[block.Id].Entry.Stack is { } entryStack
                && entryStack.Count != block.EntryStack.Count)
                errors.Add($"B{block.Id} entry stack depth disagrees with worklist");
            if (analysis.Blocks[block.Id].Exit.Stack is { } exitStack
                && exitStack.Count != block.ExitStack.Count)
                errors.Add($"B{block.Id} exit stack depth disagrees with worklist");
            if (block.EntryVariables.Count != graph.Variables.Count
                || block.ExitVariables.Count != graph.Variables.Count)
                errors.Add($"B{block.Id} does not carry every tracked variable");

            VerifyPhis(graph, analysis, block, valueById, errors);
            foreach (var instruction in block.Instructions)
            {
                foreach (int output in instruction.Outputs)
                {
                    if (!valueById.TryGetValue(output, out var value))
                    {
                        errors.Add($"B{block.Id} instruction {instruction.Ordinal} defines missing %{output}");
                        continue;
                    }
                    if (value.Kind != SsaValueKind.Operation
                        || value.DefinitionBlockId != block.Id
                        || value.DefinitionInstructionOrdinal != instruction.Ordinal)
                        errors.Add($"%{output} has an inconsistent operation definition");
                }
            }

            VerifyIds(block.EntryStack, valueById, errors, $"B{block.Id} entry stack");
            VerifyIds(block.ExitStack, valueById, errors, $"B{block.Id} exit stack");
            VerifyIds(block.EntryVariables.Values, valueById, errors,
                $"B{block.Id} entry variables");
            VerifyIds(block.ExitVariables.Values, valueById, errors,
                $"B{block.Id} exit variables");
        }

        var recomputedUses = BuildUses(graph.Blocks);
        if (!recomputedUses.SequenceEqual(graph.Uses))
            errors.Add("stored SSA use table differs from instruction/phi operands");
        foreach (var use in graph.Uses)
            if (!valueById.ContainsKey(use.ValueId))
                errors.Add($"use references undefined value %{use.ValueId}");

        VerifyDefinitionCoverage(graph, valueById, errors);
        VerifyDominance(graph, valueById, errors);
        return new SsaVerificationResult(errors);
    }

    public static SsaStatistics Statistics(SsaGraph graph) => new(
        graph.Blocks.Count(block => block.Reachable),
        graph.Blocks.Count(block => !block.Reachable),
        graph.Values.Count,
        graph.Blocks.Sum(block => block.Phis.Count),
        graph.Blocks.Sum(block => block.Instructions.Count),
        graph.Uses.Count);

    private static void VerifyPhis(
        SsaGraph graph,
        WorklistAnalysisResult analysis,
        SsaBlock block,
        IReadOnlyDictionary<int, SsaValue> values,
        List<string> errors)
    {
        var predecessors = SsaControlFlow.Incoming(graph.Source, graph.Source.Blocks[block.Id])
            .Where(edge => analysis.Blocks[edge.SourceBlockId].Entry.Reachable)
            .Select(edge => edge.SourceBlockId)
            .Distinct()
            .Order()
            .ToArray();
        foreach (var phi in block.Phis)
        {
            if (!values.TryGetValue(phi.Result.Id, out var result)
                || result.Kind != SsaValueKind.Phi
                || result.DefinitionBlockId != block.Id)
                errors.Add($"B{block.Id} phi result %{phi.Result.Id} has no matching definition");
            var actualPredecessors = phi.Inputs
                .Where(input => input.Kind == SsaPhiInputKind.Predecessor)
                .Select(input => input.PredecessorBlockId)
                .Order()
                .ToArray();
            if (!actualPredecessors.SequenceEqual(predecessors.Cast<int?>()))
                errors.Add($"B{block.Id} phi %{phi.Result.Id} predecessor set is incomplete");
            int entryInputs = phi.Inputs.Count(input => input.Kind == SsaPhiInputKind.MethodEntry);
            if (entryInputs != (block.Id == 0 ? 1 : 0))
                errors.Add($"B{block.Id} phi %{phi.Result.Id} has invalid method-entry arity");
            foreach (var input in phi.Inputs)
            {
                if (!values.TryGetValue(input.ValueId, out var incoming))
                {
                    errors.Add($"B{block.Id} phi %{phi.Result.Id} uses missing %{input.ValueId}");
                    continue;
                }
                if (!TypeCompatible(phi.Result.AbstractValue, incoming.AbstractValue))
                    errors.Add($"B{block.Id} phi %{phi.Result.Id} type {phi.Result.AbstractValue} "
                        + $"is incompatible with %{incoming.Id}:{incoming.AbstractValue}");
            }
        }
    }

    private static void VerifyDefinitionCoverage(
        SsaGraph graph,
        IReadOnlyDictionary<int, SsaValue> values,
        List<string> errors)
    {
        var phiResults = graph.Blocks.SelectMany(block => block.Phis)
            .Select(phi => phi.Result.Id).ToHashSet();
        var operationResults = graph.Blocks.SelectMany(block => block.Instructions)
            .SelectMany(instruction => instruction.Outputs).ToHashSet();
        var entryValues = graph.Blocks.SelectMany(block => block.EntryStack)
            .ToHashSet();
        foreach (var value in values.Values)
        {
            bool covered = value.Kind switch
            {
                SsaValueKind.InitialArgument or SsaValueKind.InitialLocal =>
                    value.DefinitionBlockId is null,
                SsaValueKind.Phi => phiResults.Contains(value.Id),
                SsaValueKind.Operation => operationResults.Contains(value.Id),
                SsaValueKind.ExceptionObject => entryValues.Contains(value.Id),
                _ => false,
            };
            if (!covered)
                errors.Add($"%{value.Id} ({value.Kind}) has no concrete SSA definition");
        }
    }

    private static void VerifyDominance(
        SsaGraph graph,
        IReadOnlyDictionary<int, SsaValue> values,
        List<string> errors)
    {
        var dominators = ComputeDominators(graph);
        foreach (var use in graph.Uses)
        {
            if (!values.TryGetValue(use.ValueId, out var value))
                continue;
            if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal)
                continue;
            int? definitionBlock = value.DefinitionBlockId;
            if (definitionBlock is null)
            {
                errors.Add($"%{value.Id} has no definition block");
                continue;
            }

            int useBlock = use.Kind == SsaUseKind.PhiInput
                && use.PredecessorBlockId is { } predecessor ? predecessor : use.BlockId;
            if (!dominators.GetValueOrDefault(useBlock, []).Contains(definitionBlock.Value))
            {
                errors.Add($"%{value.Id} defined in B{definitionBlock} does not dominate "
                    + $"its use in B{useBlock}");
                continue;
            }
            if (definitionBlock == useBlock
                && value.Kind == SsaValueKind.Operation
                && use.InstructionOrdinal is { } useOrdinal
                && value.DefinitionInstructionOrdinal >= useOrdinal)
                errors.Add($"%{value.Id} is used before its definition in B{useBlock}");
        }
    }

    private static IReadOnlyDictionary<int, HashSet<int>> ComputeDominators(SsaGraph graph)
    {
        var reachable = graph.Blocks.Where(block => block.Reachable)
            .Select(block => block.Id).ToHashSet();
        var result = reachable.ToDictionary(id => id,
            id => id == 0 ? new HashSet<int> { 0 } : new HashSet<int>(reachable));
        bool changed;
        do
        {
            changed = false;
            foreach (int id in reachable.Where(id => id != 0))
            {
                var predecessors = SsaControlFlow.Incoming(graph.Source, graph.Source.Blocks[id])
                    .Select(edge => edge.SourceBlockId)
                    .Where(reachable.Contains)
                    .Distinct()
                    .ToArray();
                if (predecessors.Length == 0)
                    continue;
                var next = new HashSet<int>(result[predecessors[0]]);
                foreach (int predecessor in predecessors.Skip(1))
                    next.IntersectWith(result[predecessor]);
                next.Add(id);
                if (!result[id].SetEquals(next))
                {
                    result[id] = next;
                    changed = true;
                }
            }
        } while (changed);
        return result;
    }

    private static bool TypeCompatible(AbstractValue result, AbstractValue incoming)
    {
        if (result.Kind == AbstractValueKind.Unknown || incoming.Kind == AbstractValueKind.Unknown)
            return true;
        if (result.Kind != incoming.Kind)
            return false;
        if (result.Kind is AbstractValueKind.ValueType or AbstractValueKind.ManagedPointer)
            return result.ExactType is null || incoming.ExactType is null
                || result.ExactType == incoming.ExactType;
        return true;
    }

    private static void VerifyIds(
        IEnumerable<int> ids,
        IReadOnlyDictionary<int, SsaValue> values,
        List<string> errors,
        string owner)
    {
        foreach (int id in ids)
            if (!values.ContainsKey(id))
                errors.Add($"{owner} references missing %{id}");
    }

    private static IReadOnlyList<SsaUse> BuildUses(IReadOnlyList<SsaBlock> blocks)
    {
        var uses = new List<SsaUse>();
        foreach (var block in blocks.Where(block => block.Reachable))
        {
            foreach (var phi in block.Phis)
                foreach (var input in phi.Inputs)
                    uses.Add(new SsaUse(input.ValueId, SsaUseKind.PhiInput,
                        block.Id, PredecessorBlockId: input.PredecessorBlockId));
            foreach (var instruction in block.Instructions)
                foreach (int input in instruction.Inputs)
                    uses.Add(new SsaUse(input, SsaUseKind.InstructionInput,
                        block.Id, instruction.Ordinal));
            if (block.Terminator is { } terminator)
                foreach (int input in terminator.Inputs)
                    uses.Add(new SsaUse(input, SsaUseKind.TerminatorInput, block.Id));
        }
        return uses;
    }
}
