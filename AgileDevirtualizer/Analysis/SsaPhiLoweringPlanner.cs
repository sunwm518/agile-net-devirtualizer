using AgileDevirtualizer.Decode;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Plans a multi-block, phi-free lowering of the SSA graph. Every value that crosses a block
/// boundary is bound to a congruence-class slot, so the CIL evaluation stack is empty at every block
/// boundary and no edge needs to be split. Any shape whose slot content cannot be proven is rejected;
/// the caller then stays on the lossless route.
/// </summary>
internal static class SsaPhiLoweringPlanner
{
    private const int EntryPosition = int.MinValue + 1;
    private const int TerminatorPosition = int.MaxValue - 1;
    private const int ExitPosition = int.MaxValue;

    public static SsaPhiLoweringPlan Plan(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (!ReferenceEquals(deadCode.Sccp.Graph, types.Graph) || !types.Converged)
            return SsaPhiLoweringPlan.Reject(deadCode, types,
                "CIL types do not belong to this SSA graph or did not converge");
        var requirements = SsaLoweringRequirementAnalyzer.Analyze(deadCode.Sccp);
        if (!requirements.PhiLoweringCandidate)
            return SsaPhiLoweringPlan.Reject(deadCode, types, $"requires {requirements.Features}");
        var graph = deadCode.Sccp.Graph;
        if (decoded.ExceptionHandlers.Count != 0 || graph.Source.ExceptionRegions.Count != 0)
            return SsaPhiLoweringPlan.Reject(deadCode, types,
                "phi lowering does not model exception regions yet");

        var executable = graph.Blocks.Where(block => block.Reachable
            && deadCode.Sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        var executableIds = executable.Select(block => block.Id).ToHashSet();
        if (!executableIds.Contains(0))
            return SsaPhiLoweringPlan.Reject(deadCode, types, "entry block is not executable");
        if (graph.Blocks.Any(block => block.Reachable && !executableIds.Contains(block.Id)))
            return SsaPhiLoweringPlan.Reject(deadCode, types,
                "reachable blocks are not all executable; constant branch folding owns this shape");
        if (!SsaPhiBlockLayout.TryOrder(graph, deadCode.Sccp, executableIds,
            out var order, out string? layoutError))
            return SsaPhiLoweringPlan.Reject(deadCode, types, layoutError!);

        var congruence = SsaPhiCongruence.Build(deadCode, types, decoded, tempLocalTypes,
            executableIds);
        if (!congruence.Valid)
            return SsaPhiLoweringPlan.Reject(deadCode, types, congruence.Reason);

        var context = new PlanContext(deadCode, types, graph, executable, executableIds,
            congruence, order);
        if (context.Error is { } contextError)
            return SsaPhiLoweringPlan.Reject(deadCode, types, contextError);

        for (int attempt = 0; attempt <= context.EffectCount + 1; attempt++)
        {
            if (!context.TrySchedule(out var blocks, out string? error))
                return SsaPhiLoweringPlan.Reject(deadCode, types, error!);
            if (context.EffectOrderPreserved(blocks, out string? disorder))
            {
                if (!context.TrySpillTypes(out var spillTypes, out string? typeError))
                    return SsaPhiLoweringPlan.Reject(deadCode, types, typeError!);
                return new SsaPhiLoweringPlan(deadCode, types, true, "eligible", order,
                    congruence.Classes, congruence.ValueClass, spillTypes,
                    context.EntryStores, blocks);
            }
            if (!context.AddEffectSpill(blocks))
                return SsaPhiLoweringPlan.Reject(deadCode, types,
                    $"phi lowering cannot preserve observable effect order ({disorder})");
        }

        return SsaPhiLoweringPlan.Reject(deadCode, types, "phi scheduling did not stabilize");
    }

    private sealed class PlanContext
    {
        private readonly DeadCodeResult _deadCode;
        private readonly SsaCilTypeResult _types;
        private readonly SsaGraph _graph;
        private readonly IReadOnlyList<SsaBlock> _executable;
        private readonly IReadOnlySet<int> _executableIds;
        private readonly SsaPhiCongruenceResult _congruence;
        private readonly IReadOnlyList<int> _order;
        private readonly Dictionary<int, SsaInstruction> _definitions = [];
        private readonly Dictionary<(int Block, int Ordinal), SsaInstruction> _byLocation = [];
        private readonly Dictionary<int, SsaInstruction> _byId = [];
        private readonly Dictionary<int, int> _liveUseCounts = [];
        private readonly Dictionary<(int Block, int Class), SsaPhi> _blockClassPhi = [];
        private readonly Dictionary<int, int> _initialClassValues = [];
        private readonly HashSet<int> _spills = [];

        public PlanContext(
            DeadCodeResult deadCode,
            SsaCilTypeResult types,
            SsaGraph graph,
            IReadOnlyList<SsaBlock> executable,
            IReadOnlySet<int> executableIds,
            SsaPhiCongruenceResult congruence,
            IReadOnlyList<int> order)
        {
            _deadCode = deadCode;
            _types = types;
            _graph = graph;
            _executable = executable;
            _executableIds = executableIds;
            _congruence = congruence;
            _order = order;

            foreach (var block in executable)
            {
                foreach (var instruction in block.Instructions)
                {
                    _byLocation[(block.Id, instruction.Ordinal)] = instruction;
                    _byId[instruction.Id] = instruction;
                    foreach (int output in instruction.Outputs)
                        _definitions[output] = instruction;
                    if (instruction.Outputs.Count <= 1)
                        continue;
                    Error = $"I{instruction.Id} has {instruction.Outputs.Count} outputs";
                    return;
                }
            }
            foreach (var phi in congruence.NeededPhis)
            {
                int blockId = phi.Result.DefinitionBlockId
                    ?? throw new InvalidOperationException("needed phi has no block");
                int classId = congruence.ValueClass[phi.Result.Id];
                if (!_blockClassPhi.TryAdd((blockId, classId), phi))
                {
                    Error = $"B{blockId} has two needed phis in one congruence class "
                        + $"(%{_blockClassPhi[(blockId, classId)].Result.Id}, "
                        + $"%{phi.Result.Id})";
                    return;
                }
            }
            foreach (var use in graph.Uses.Where(IsLiveNonPhiUse))
                _liveUseCounts[use.ValueId] = _liveUseCounts.GetValueOrDefault(use.ValueId) + 1;
            foreach (var pair in _liveUseCounts)
            {
                if (pair.Value > 1 && !congruence.ValueClass.ContainsKey(pair.Key)
                    && !deadCode.ConstantReplacements.ContainsKey(pair.Key)
                    && _definitions.ContainsKey(pair.Key))
                    _spills.Add(pair.Key);
            }
            EntryStores = BuildEntryStores();
        }

        public string? Error { get; private set; }

        public IReadOnlyList<SsaClassStore> EntryStores { get; } = [];

        public bool TrySchedule(
            out IReadOnlyDictionary<int, SsaPhiBlockPlan> blocks,
            out string? error)
        {
            var result = new Dictionary<int, SsaPhiBlockPlan>();
            blocks = result;
            foreach (int blockId in _order)
            {
                var scheduled = ScheduleBlock(_graph.Blocks[blockId]);
                if (scheduled.Plan is null)
                {
                    error = scheduled.Error ?? $"B{blockId} could not be scheduled";
                    return false;
                }
                result[blockId] = scheduled.Plan;
            }
            error = null;
            return true;
        }

        private sealed record BlockSchedule(SsaPhiBlockPlan? Plan, string? Error);

        public bool EffectOrderPreserved(
            IReadOnlyDictionary<int, SsaPhiBlockPlan> blocks,
            out string? disorder)
        {
            foreach (var block in _executable)
            {
                var expected = block.Instructions
                    .Where(instruction => IsLive(instruction) && HasEffect(instruction))
                    .Select(instruction => instruction.Id).ToArray();
                var planned = blocks[block.Id].PlannedInstructionIds
                    .Where(id => HasEffect(_byId[id])).ToArray();
                if (expected.SequenceEqual(planned))
                    continue;
                disorder = $"B{block.Id} effects [{string.Join(",", expected)}] "
                    + $"scheduled as [{string.Join(",", planned)}]";
                return false;
            }
            disorder = null;
            return true;
        }

        /// <summary>
        /// Pins exactly one displaced observable operation per attempt. Spilling every effectful
        /// result at once would also pin the single-use results whose forwarding is what makes this
        /// route smaller than the lossless baseline, so the fix has to stay minimal.
        /// </summary>
        public bool AddEffectSpill(IReadOnlyDictionary<int, SsaPhiBlockPlan> blocks)
        {
            foreach (var block in _executable)
            {
                var expected = block.Instructions
                    .Where(instruction => IsLive(instruction) && HasEffect(instruction))
                    .Select(instruction => instruction.Id).ToArray();
                var planned = blocks[block.Id].PlannedInstructionIds
                    .Where(id => HasEffect(_byId[id])).ToArray();
                if (expected.SequenceEqual(planned))
                    continue;
                for (int index = 0; index < expected.Length; index++)
                {
                    if (index < planned.Length && planned[index] == expected[index])
                        continue;
                    if (TryPin(expected[index]))
                        return true;
                    if (index < planned.Length && TryPin(planned[index]))
                        return true;
                    break;
                }
            }
            return false;

            bool TryPin(int instructionId)
            {
                var instruction = _byId[instructionId];
                if (instruction.Outputs.Count != 1)
                    return false;
                int output = instruction.Outputs[0];
                return !_congruence.ValueClass.ContainsKey(output)
                    && !_deadCode.ConstantReplacements.ContainsKey(output)
                    && LiveUses(output) > 0
                    && _spills.Add(output);
            }
        }

        public int EffectCount => _executable.Sum(block => block.Instructions
            .Count(instruction => IsLive(instruction) && HasEffect(instruction)));

        public bool TrySpillTypes(
            out IReadOnlyDictionary<int, TypeSignature> result,
            out string? error)
        {
            var mapped = new Dictionary<int, TypeSignature>();
            foreach (int valueId in _spills.Order())
            {
                if (_types.Values[valueId] is not { Kind: SsaCilTypeKind.Exact, Type: { } type })
                {
                    result = mapped;
                    error = $"spill %{valueId} has no exact CIL type ({_types.Values[valueId]})";
                    return false;
                }
                mapped[valueId] = type;
            }
            result = mapped;
            error = null;
            return true;
        }

        private BlockSchedule ScheduleBlock(SsaBlock block)
        {
            string? failure = null;
            var roots = new List<SsaPhiBlockRoot>();
            foreach (var instruction in block.Instructions.Where(IsLive))
            {
                int? output = instruction.Outputs.Count == 1 ? instruction.Outputs[0] : null;
                bool effect = HasEffect(instruction);
                int uses = output is { } value ? LiveUses(value) : 0;
                if (output is { } classValue
                    && _congruence.ValueClass.TryGetValue(classValue, out int classId))
                {
                    roots.Add(new SsaPhiBlockRoot(instruction.Id, instruction.Ordinal,
                        null, classId, false));
                }
                else if (output is { } spillValue && _spills.Contains(spillValue))
                {
                    roots.Add(new SsaPhiBlockRoot(instruction.Id, instruction.Ordinal,
                        spillValue, null, false));
                }
                else if (effect && (output is null || uses == 0))
                {
                    roots.Add(new SsaPhiBlockRoot(instruction.Id, instruction.Ordinal,
                        null, null, output is not null));
                }
            }

            if (!TryExitStores(block, roots, out var exitStores, out string? exitError))
                return new BlockSchedule(null, exitError);
            var events = BuildEvents(block, roots, exitStores);
            var planned = new List<int>();
            var emitted = new HashSet<int>();
            var createdSpills = new HashSet<int>();

            foreach (var root in roots)
            {
                var instruction = _byLocation[(block.Id, root.Ordinal)];
                foreach (int input in instruction.Inputs)
                    if (!AppendValue(input, root.Ordinal))
                        return new BlockSchedule(null, failure);
                if (!AppendInstruction(instruction))
                    return new BlockSchedule(null, failure);
                if (root.SpillValueId is { } spill)
                    createdSpills.Add(spill);
            }

            if (block.Terminator is not { } terminator)
                return new BlockSchedule(null, $"B{block.Id} has no SSA terminator");
            foreach (int input in terminator.Inputs)
                if (!AppendValue(input, TerminatorPosition))
                    return new BlockSchedule(null, failure);

            return new BlockSchedule(new SsaPhiBlockPlan(block.Id,
                block.Phis.Where(phi => _congruence.ValueClass.ContainsKey(phi.Result.Id))
                    .Select(phi => _congruence.ValueClass[phi.Result.Id]).Order().ToArray(),
                roots, exitStores, planned), null);

            bool AppendValue(int valueId, int position)
            {
                if (_deadCode.ConstantReplacements.ContainsKey(valueId))
                    return true;
                if (_congruence.ValueClass.TryGetValue(valueId, out int classId))
                {
                    int? available = Available(events, classId, position);
                    if (available == valueId)
                        return true;
                    failure = $"B{block.Id} reads %{valueId} from class C{classId} at {position} "
                        + $"where the slot holds "
                        + (available is { } other ? $"%{other}" : "nothing");
                    return false;
                }
                if (_spills.Contains(valueId))
                {
                    if (createdSpills.Contains(valueId))
                        return true;
                    failure = $"B{block.Id} uses spill %{valueId} before its definition";
                    return false;
                }
                var value = _graph.Value(valueId);
                if (value.Kind is SsaValueKind.InitialArgument or SsaValueKind.InitialLocal)
                    return true;
                if (value.Kind != SsaValueKind.Operation
                    || !_definitions.TryGetValue(valueId, out var definition))
                {
                    failure = $"B{block.Id} value %{valueId} ({value.Kind}) has no slot";
                    return false;
                }
                if (definition.BlockId != block.Id)
                {
                    failure = $"B{block.Id} uses %{valueId} defined in B{definition.BlockId} "
                        + "without a slot";
                    return false;
                }
                if (!IsLive(definition))
                {
                    failure = $"B{block.Id} definition I{definition.Id} of %{valueId} is not live";
                    return false;
                }
                foreach (int input in definition.Inputs)
                    if (!AppendValue(input, definition.Ordinal))
                        return false;
                return AppendInstruction(definition);
            }

            bool AppendInstruction(SsaInstruction instruction)
            {
                if (emitted.Add(instruction.Id))
                {
                    planned.Add(instruction.Id);
                    return true;
                }
                failure = $"B{block.Id} would emit I{instruction.Id} more than once";
                return false;
            }
        }

        /// <summary>
        /// Determines the single value each congruence class must hold when the block exits, taken
        /// from the phi inputs its successors actually read. Two different required values for one
        /// class mean the class interferes with itself and the method is rejected.
        /// </summary>
        private bool TryExitStores(
            SsaBlock block,
            IReadOnlyList<SsaPhiBlockRoot> roots,
            out IReadOnlyList<SsaClassStore> stores,
            out string? error)
        {
            var required = new Dictionary<int, HashSet<int>>();
            foreach (var phi in _congruence.NeededPhis)
            {
                int classId = _congruence.ValueClass[phi.Result.Id];
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, _deadCode.Sccp))
                {
                    if (input.PredecessorBlockId != block.Id)
                        continue;
                    if (!required.TryGetValue(classId, out var values))
                        required[classId] = values = [];
                    values.Add(input.ValueId);
                }
            }

            var result = new List<SsaClassStore>();
            stores = result;
            var events = BuildEvents(block, roots, []);
            foreach (var pair in required.OrderBy(pair => pair.Key))
            {
                if (pair.Value.Count != 1)
                {
                    error = $"B{block.Id} must leave {pair.Value.Count} different values in "
                        + $"class C{pair.Key}: "
                        + string.Join(", ", pair.Value.Order().Select(id => $"%{id}"));
                    return false;
                }
                int value = pair.Value.Single();
                if (_deadCode.ConstantReplacements.TryGetValue(value, out object? constant))
                {
                    result.Add(new SsaClassStore(pair.Key, SsaClassStoreSource.Constant,
                        value, constant));
                    continue;
                }
                int? available = Available(events, pair.Key, ExitPosition);
                if (available == value)
                    continue;
                error = $"B{block.Id} must leave %{value} in class C{pair.Key} but the slot holds "
                    + (available is { } other ? $"%{other}" : "nothing");
                return false;
            }
            error = null;
            return true;
        }

        private List<(int Position, int ClassId, int ValueId)> BuildEvents(
            SsaBlock block,
            IReadOnlyList<SsaPhiBlockRoot> roots,
            IReadOnlyList<SsaClassStore> exitStores)
        {
            var events = new List<(int Position, int ClassId, int ValueId)>();
            if (block.Id == 0)
                foreach (var pair in _initialClassValues)
                    events.Add((EntryPosition, pair.Key, pair.Value));
            foreach (var phi in block.Phis)
                if (_congruence.ValueClass.TryGetValue(phi.Result.Id, out int classId))
                    events.Add((-1, classId, phi.Result.Id));
            foreach (var root in roots.Where(root => root.ClassId is not null))
                events.Add((root.Ordinal, root.ClassId!.Value,
                    _byLocation[(block.Id, root.Ordinal)].Outputs[0]));
            foreach (var store in exitStores)
                events.Add((ExitPosition, store.ClassId, store.ValueId));
            events.Sort((left, right) => left.Position.CompareTo(right.Position));
            return events;
        }

        private static int? Available(
            IReadOnlyList<(int Position, int ClassId, int ValueId)> events,
            int classId,
            int position)
        {
            int? value = null;
            foreach (var item in events)
            {
                if (item.Position >= position)
                    break;
                if (item.ClassId == classId)
                    value = item.ValueId;
            }
            return value;
        }

        private IReadOnlyList<SsaClassStore> BuildEntryStores()
        {
            var result = new List<SsaClassStore>();
            foreach (var phiClass in _congruence.Classes)
            {
                var initial = phiClass.Members.Select(_graph.Value).FirstOrDefault(value =>
                    value.Kind is SsaValueKind.InitialLocal or SsaValueKind.InitialArgument);
                if (initial is null || initial.Variable is not { } variable)
                    continue;
                _initialClassValues[phiClass.Id] = initial.Id;
                if (phiClass.ReusedVariable == variable)
                    continue;
                result.Add(new SsaClassStore(phiClass.Id, SsaClassStoreSource.InitialVariable,
                    initial.Id, Variable: variable));
            }
            return result;
        }

        private bool IsLive(SsaInstruction instruction) =>
            _deadCode.LiveInstructionIds.Contains(instruction.Id);

        private static bool HasEffect(SsaInstruction instruction) =>
            !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation);

        private int LiveUses(int valueId) => _liveUseCounts.GetValueOrDefault(valueId);

        private bool IsLiveNonPhiUse(SsaUse use) => use.Kind switch
        {
            SsaUseKind.TerminatorInput => _executableIds.Contains(use.BlockId),
            SsaUseKind.InstructionInput => use.InstructionOrdinal is { } ordinal
                && _byLocation.TryGetValue((use.BlockId, ordinal), out var consumer)
                && IsLive(consumer),
            _ => false,
        };
    }
}

