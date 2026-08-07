using AsmResolver.DotNet;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Converts the reachable Semantic CFG into stack-to-SSA form. Block-entry values are explicit phi
/// nodes, which makes loops and exception-region joins finite without changing the emitted CIL.
/// </summary>
internal static class SsaGraphBuilder
{
    public static SsaGraph Build(
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        MethodDefinition target)
    {
        if (!ReferenceEquals(graph, analysis.Graph))
            throw new ArgumentException("SSA analysis belongs to a different CFG", nameof(analysis));
        if (!analysis.Converged)
            throw new InvalidOperationException("SSA requires a converged worklist");

        var variables = CollectVariables(graph);
        var values = new List<SsaValue>();
        int nextValueId = 0;
        int nextInstructionId = 0;

        SsaValue NewValue(
            SsaValueKind kind,
            AbstractValue abstractValue,
            int? blockId = null,
            int? instructionOrdinal = null,
            SsaVariableSlot? variable = null,
            int? stackSlot = null)
        {
            var value = new SsaValue(nextValueId++, kind, abstractValue, blockId,
                instructionOrdinal, variable, stackSlot);
            values.Add(value);
            return value;
        }

        var initialValues = variables.ToDictionary(variable => variable,
            variable => NewValue(
                variable.Kind == SsaVariableKind.Argument
                    ? SsaValueKind.InitialArgument : SsaValueKind.InitialLocal,
                SsaValueInference.ForInitialVariable(variable), variable: variable));
        var mutable = new MutableBlock[graph.Blocks.Count];

        foreach (var block in graph.Blocks)
        {
            var state = analysis.Blocks[block.Id];
            var current = new MutableBlock(block.Id, state.Entry.Reachable);
            mutable[block.Id] = current;
            if (!current.Reachable)
                continue;
            if (state.Entry.Stack is null)
                throw new InvalidOperationException($"B{block.Id} has no stable entry stack shape");

            var incoming = ReachableIncoming(graph, analysis, block).ToArray();
            bool entryHasBackedge = block.Id == 0 && incoming.Length > 0;
            foreach (var variable in variables)
            {
                if (block.Id == 0 && !entryHasBackedge)
                {
                    current.EntryVariables[variable] = initialValues[variable].Id;
                    continue;
                }

                var abstractValue = EntryVariableValue(state.Entry, variable);
                var result = NewValue(SsaValueKind.Phi, abstractValue, block.Id,
                    variable: variable);
                var phi = new SsaPhi(result, SsaPhiLocationKind.Variable, variable,
                    null, new List<SsaPhiInput>());
                current.Phis.Add(phi);
                current.EntryVariables[variable] = result.Id;
            }

            bool exceptionalEntry = incoming.Length > 0
                && incoming.All(edge => IsExceptionEdge(edge.Kind));
            if (exceptionalEntry)
            {
                bool hasExceptionObject = incoming.All(edge =>
                    ControlFlowEdgeSemantics.SeedsExceptionObject(edge.Kind));
                int expectedStack = hasExceptionObject ? 1 : 0;
                if (state.Entry.Stack.Count != expectedStack)
                    throw new InvalidOperationException(
                        $"B{block.Id} exceptional entry stack has {state.Entry.Stack.Count}, "
                        + $"expected {expectedStack}");
                if (hasExceptionObject)
                {
                    var exception = NewValue(SsaValueKind.ExceptionObject,
                        state.Entry.Stack[0], block.Id, stackSlot: 0);
                    current.EntryStack.Add(exception.Id);
                }
            }
            else
            {
                if (incoming.Any(edge => IsExceptionEdge(edge.Kind)))
                    throw new InvalidOperationException(
                        $"B{block.Id} mixes exceptional and normal evaluation-stack entry: "
                        + string.Join(", ", incoming.Select(edge =>
                            $"B{edge.SourceBlockId}:{edge.Kind} "
                            + $"{graph.Blocks[edge.SourceBlockId].RegionPath}")));
                for (int slot = 0; slot < state.Entry.Stack.Count; slot++)
                {
                    if (block.Id == 0)
                        throw new InvalidOperationException(
                            "method entry has a non-empty evaluation stack");
                    var result = NewValue(SsaValueKind.Phi, state.Entry.Stack[slot], block.Id,
                        stackSlot: slot);
                    var phi = new SsaPhi(result, SsaPhiLocationKind.EvaluationStack,
                        null, slot, new List<SsaPhiInput>());
                    current.Phis.Add(phi);
                    current.EntryStack.Add(result.Id);
                }
            }
        }

        bool returnsValue = target.Signature is { } signature
            && !signature.ReturnType.IsTypeOf("System", "Void");
        foreach (var block in graph.Blocks)
        {
            var current = mutable[block.Id];
            if (!current.Reachable)
                continue;
            var stack = current.EntryStack.ToList();
            var variableState = new Dictionary<SsaVariableSlot, int>(current.EntryVariables);
            int ordinal = 0;

            foreach (var operation in block.Operations)
            {
                var effect = SsaStackSemantics.ForOperation(operation);
                var inputs = new List<int>();
                var outputs = new List<int>();
                switch (effect.Behavior)
                {
                    case SsaOperationBehavior.NoEffect:
                        break;
                    case SsaOperationBehavior.LoadVariable:
                        var loadedSlot = VariableFor(operation);
                        int loaded = variableState[loadedSlot];
                        inputs.Add(loaded);
                        stack.Add(loaded);
                        break;
                    case SsaOperationBehavior.StoreVariable:
                        inputs.AddRange(Pop(stack, effect.PopCount, block.Id, operation.Code));
                        variableState[VariableFor(operation)] = inputs[0];
                        break;
                    case SsaOperationBehavior.Duplicate:
                        int duplicate = Peek(stack, block.Id, operation.Code);
                        inputs.Add(duplicate);
                        stack.Add(duplicate);
                        break;
                    case SsaOperationBehavior.Pop:
                        inputs.AddRange(Pop(stack, effect.PopCount, block.Id, operation.Code));
                        break;
                    case SsaOperationBehavior.General:
                        inputs.AddRange(Pop(stack, effect.PopCount, block.Id, operation.Code));
                        var inputTypes = inputs.Select(id => values[id].AbstractValue).ToArray();
                        for (int outputIndex = 0; outputIndex < effect.PushCount; outputIndex++)
                        {
                            var inferred = outputIndex == 0
                                ? SsaValueInference.ForOperation(operation, inputTypes)
                                : AbstractValue.Unknown;
                            var result = NewValue(SsaValueKind.Operation, inferred, block.Id,
                                ordinal);
                            outputs.Add(result.Id);
                            stack.Add(result.Id);
                        }
                        break;
                    default:
                        throw new InvalidOperationException(
                            $"unknown SSA behavior {effect.Behavior}");
                }

                current.Instructions.Add(new SsaInstruction(nextInstructionId++, block.Id,
                    ordinal, operation, inputs, outputs));
                ordinal++;
            }

            int terminatorPops = SsaStackSemantics.TerminatorPopCount(
                block.Terminator, returnsValue);
            var terminatorInputs = Pop(stack, terminatorPops, block.Id,
                block.Terminator.Kind.ToString());
            current.Terminator = new SsaTerminator(block.Terminator, terminatorInputs);
            current.ExitStack.AddRange(stack);
            foreach (var pair in variableState)
                current.ExitVariables[pair.Key] = pair.Value;
        }

        FillPhiInputs(graph, analysis, mutable, variables, initialValues);
        var blocks = mutable.Select(block => block.Freeze()).ToArray();
        var uses = BuildUses(blocks);
        return new SsaGraph(graph, blocks, values, uses, variables);
    }

    private static IReadOnlyList<SsaVariableSlot> CollectVariables(
        SemanticControlFlowGraph graph) => graph.Blocks
        .SelectMany(block => block.Operations)
        .Select(operation => TryVariableFor(operation, out var variable)
            ? (SsaVariableSlot?)variable : null)
        .Where(variable => variable.HasValue)
        .Select(variable => variable!.Value)
        .Distinct()
        .OrderBy(variable => variable.Kind)
        .ThenBy(variable => variable.Temporary)
        .ThenBy(variable => variable.Index)
        .ToArray();

    private static SsaVariableSlot VariableFor(SemanticOperation operation) =>
        TryVariableFor(operation, out var variable)
            ? variable
            : throw new InvalidOperationException(
                $"{operation.Code} has no semantic variable operand");

    private static bool TryVariableFor(
        SemanticOperation operation,
        out SsaVariableSlot variable)
    {
        if (operation.Operand is SemanticLocalReference local)
        {
            variable = new SsaVariableSlot(SsaVariableKind.Local,
                local.Index, local.Temporary);
            return true;
        }
        if (operation.Operand is SemanticArgumentReference argument)
        {
            variable = new SsaVariableSlot(SsaVariableKind.Argument, argument.Index);
            return true;
        }
        variable = default;
        return false;
    }

    private static AbstractValue EntryVariableValue(
        AbstractState state,
        SsaVariableSlot variable)
    {
        if (variable.Kind != SsaVariableKind.Local)
            return AbstractValue.Unknown;
        return state.Locals.GetValueOrDefault(
            new SemanticLocalReference(variable.Index, variable.Temporary),
            AbstractValue.Unknown);
    }

    private static IEnumerable<ControlFlowEdge> ReachableIncoming(
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        BasicBlock block) => SsaControlFlow.Incoming(graph, block)
        .Where(edge => analysis.Blocks[edge.SourceBlockId].Entry.Reachable)
        .GroupBy(edge => edge.SourceBlockId)
        .Select(group => group.First());

    private static bool IsExceptionEdge(ControlFlowEdgeKind kind) =>
        ControlFlowEdgeSemantics.IsException(kind);

    private static IReadOnlyList<int> Pop(
        List<int> stack,
        int count,
        int blockId,
        object operation)
    {
        if (stack.Count < count)
            throw new InvalidOperationException(
                $"B{blockId} stack underflow at {operation}: need {count}, have {stack.Count}");
        var values = stack.GetRange(stack.Count - count, count);
        stack.RemoveRange(stack.Count - count, count);
        return values;
    }

    private static int Peek(List<int> stack, int blockId, object operation) =>
        stack.Count > 0
            ? stack[^1]
            : throw new InvalidOperationException($"B{blockId} stack underflow at {operation}");

    private static void FillPhiInputs(
        SemanticControlFlowGraph graph,
        WorklistAnalysisResult analysis,
        IReadOnlyList<MutableBlock> blocks,
        IReadOnlyList<SsaVariableSlot> variables,
        IReadOnlyDictionary<SsaVariableSlot, SsaValue> initialValues)
    {
        foreach (var sourceBlock in graph.Blocks)
        {
            if (!blocks[sourceBlock.Id].Reachable)
                continue;
            var outgoing = SsaControlFlow.Outgoing(graph, sourceBlock).ToArray();
            foreach (var edge in outgoing)
            {
                var target = blocks[edge.TargetBlockId];
                if (!target.Reachable)
                    continue;
                if (outgoing.Any(other => other != edge
                    && other.TargetBlockId == edge.TargetBlockId))
                {
                    var first = outgoing
                        .First(other => other.TargetBlockId == edge.TargetBlockId);
                    if (!ReferenceEquals(first, edge))
                        continue;
                }

                foreach (var variable in variables)
                {
                    var phi = target.Phis.SingleOrDefault(item =>
                        item.LocationKind == SsaPhiLocationKind.Variable
                        && item.Variable == variable);
                    if (phi is null)
                        continue;
                    MutableInputs(phi).Add(new SsaPhiInput(SsaPhiInputKind.Predecessor,
                        sourceBlock.Id, blocks[sourceBlock.Id].ExitVariables[variable], edge.Kind));
                }

                if (IsExceptionEdge(edge.Kind))
                    continue;
                var stackPhis = target.Phis
                    .Where(phi => phi.LocationKind == SsaPhiLocationKind.EvaluationStack)
                    .OrderBy(phi => phi.StackSlot)
                    .ToArray();
                if (stackPhis.Length != blocks[sourceBlock.Id].ExitStack.Count)
                    throw new InvalidOperationException(
                        $"edge B{sourceBlock.Id}->B{target.Id} stack arity "
                        + $"{blocks[sourceBlock.Id].ExitStack.Count}!={stackPhis.Length}");
                for (int slot = 0; slot < stackPhis.Length; slot++)
                {
                    MutableInputs(stackPhis[slot]).Add(new SsaPhiInput(
                        SsaPhiInputKind.Predecessor, sourceBlock.Id,
                        blocks[sourceBlock.Id].ExitStack[slot], edge.Kind));
                }
            }
        }

        var entry = blocks.FirstOrDefault();
        if (entry is null || !entry.Reachable)
            return;
        foreach (var variable in variables)
        {
            var phi = entry.Phis.SingleOrDefault(item =>
                item.LocationKind == SsaPhiLocationKind.Variable
                && item.Variable == variable);
            if (phi is not null)
            {
                MutableInputs(phi).Insert(0, new SsaPhiInput(
                    SsaPhiInputKind.MethodEntry, null, initialValues[variable].Id));
            }
        }
    }

    private static List<SsaPhiInput> MutableInputs(SsaPhi phi) =>
        (List<SsaPhiInput>)phi.Inputs;

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

    private sealed class MutableBlock
    {
        public MutableBlock(int id, bool reachable)
        {
            Id = id;
            Reachable = reachable;
        }

        public int Id { get; }
        public bool Reachable { get; }
        public List<SsaPhi> Phis { get; } = [];
        public List<SsaInstruction> Instructions { get; } = [];
        public SsaTerminator? Terminator { get; set; }
        public List<int> EntryStack { get; } = [];
        public List<int> ExitStack { get; } = [];
        public Dictionary<SsaVariableSlot, int> EntryVariables { get; } = [];
        public Dictionary<SsaVariableSlot, int> ExitVariables { get; } = [];

        public SsaBlock Freeze() => new(Id, Reachable, Phis.ToArray(),
            Instructions.ToArray(), Terminator, EntryStack.ToArray(), ExitStack.ToArray(),
            new Dictionary<SsaVariableSlot, int>(EntryVariables),
            new Dictionary<SsaVariableSlot, int>(ExitVariables));
    }
}
