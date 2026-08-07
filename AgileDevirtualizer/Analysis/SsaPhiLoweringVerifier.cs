namespace AgileDevirtualizer.Analysis;

internal sealed record SsaPhiLoweringVerification(
    IReadOnlyList<string> Errors,
    int Classes,
    int ClassStores,
    int Spills,
    int Blocks)
{
    public bool Valid => Errors.Count == 0;

    public override string ToString() => Valid
        ? $"valid: classes={Classes} classStores={ClassStores} spills={Spills} blocks={Blocks}"
        : $"invalid: {string.Join(" | ", Errors.Take(5))}";
}

/// <summary>
/// Re-derives the phi-lowering invariants from the SSA graph alone and compares them with the plan.
/// The verifier never consults the planner's intermediate state, so a planning bug cannot hide here.
/// </summary>
internal static class SsaPhiLoweringVerifier
{
    public static SsaPhiLoweringVerification Verify(SsaPhiLoweringPlan plan)
    {
        var errors = new List<string>();
        if (!plan.Eligible)
            return new SsaPhiLoweringVerification([$"plan is not eligible: {plan.Reason}"],
                0, 0, 0, 0);

        var graph = plan.DeadCode.Sccp.Graph;
        var sccp = plan.DeadCode.Sccp;
        var executable = graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        var executableIds = executable.Select(block => block.Id).ToHashSet();

        VerifyLayout(plan, executableIds, errors);
        VerifyClasses(plan, graph, errors);
        VerifyPhiCoverage(plan, executable, sccp, errors);
        VerifyBlockPlans(plan, executable, errors);
        VerifySlotContents(plan, executable, sccp, errors);

        return new SsaPhiLoweringVerification(errors, plan.Classes.Count,
            plan.TotalClassStores, plan.SpillTypes.Count, plan.Blocks.Count);
    }

    private static void VerifyLayout(
        SsaPhiLoweringPlan plan,
        IReadOnlySet<int> executableIds,
        List<string> errors)
    {
        if (!plan.BlockOrder.ToHashSet().SetEquals(executableIds))
            errors.Add("block order does not cover exactly the executable blocks");
        if (plan.BlockOrder.Count != plan.BlockOrder.Distinct().Count())
            errors.Add("block order repeats a block");
        if (plan.BlockOrder.Count > 0 && plan.BlockOrder[0] != 0)
            errors.Add("block order does not start at the entry block");
        if (!plan.Blocks.Keys.ToHashSet().SetEquals(executableIds))
            errors.Add("block plans do not cover exactly the executable blocks");
    }

    private static void VerifyClasses(
        SsaPhiLoweringPlan plan,
        SsaGraph graph,
        List<string> errors)
    {
        var seen = new HashSet<int>();
        foreach (var phiClass in plan.Classes)
        {
            foreach (int member in phiClass.Members)
            {
                if (!seen.Add(member))
                    errors.Add($"%{member} belongs to more than one congruence class");
                if (!plan.ValueClass.TryGetValue(member, out int mapped)
                    || mapped != phiClass.Id)
                    errors.Add($"%{member} is not mapped to C{phiClass.Id}");
                if (plan.DeadCode.ConstantReplacements.ContainsKey(member))
                    errors.Add($"C{phiClass.Id} member %{member} is constant folded");
                if (plan.SpillTypes.ContainsKey(member))
                    errors.Add($"C{phiClass.Id} member %{member} also has a private spill");
            }
            var exact = plan.Types.Values[phiClass.Members.Min()];
            if (exact is not { Kind: SsaCilTypeKind.Exact })
                continue;
            foreach (int member in phiClass.Members)
            {
                var memberType = plan.Types.Values[member];
                if (memberType.Kind == SsaCilTypeKind.Null)
                    continue;
                if (memberType is { Kind: SsaCilTypeKind.Exact, Type: { } type }
                    && type.FullName != phiClass.Type.FullName)
                    errors.Add($"C{phiClass.Id} member %{member} is {type.FullName}, "
                        + $"not {phiClass.Type.FullName}");
            }
            if (phiClass.ReusedVariable is not { } variable)
                continue;
            if (!phiClass.Members.Any(member => graph.Value(member) is
                { Kind: SsaValueKind.InitialLocal or SsaValueKind.InitialArgument } initial
                && initial.Variable == variable))
                errors.Add($"C{phiClass.Id} reuses {variable} without owning its initial value");
            if (variable.Kind != SsaVariableKind.Argument)
                continue;
            if (plan.EntryStores.Any(store => store.ClassId == phiClass.Id)
                || plan.Blocks.Values.Any(block =>
                    block.ExitStores.Any(store => store.ClassId == phiClass.Id)
                    || block.Roots.Any(root => root.ClassId == phiClass.Id)))
                errors.Add($"C{phiClass.Id} is hosted in argument {variable} but receives a store");
        }
        foreach (int member in plan.ValueClass.Keys)
            if (!seen.Contains(member))
                errors.Add($"%{member} is mapped to a class that does not list it");
    }

    /// <summary>Every needed phi must be represented, and no class may hold two per block.</summary>
    private static void VerifyPhiCoverage(
        SsaPhiLoweringPlan plan,
        IReadOnlyList<SsaBlock> executable,
        SccpResult sccp,
        List<string> errors)
    {
        var perBlockClass = new HashSet<(int, int)>();
        foreach (var block in executable)
        {
            foreach (var phi in block.Phis)
            {
                bool needed = plan.DeadCode.LiveValueIds.Contains(phi.Result.Id)
                    && !plan.DeadCode.ConstantReplacements.ContainsKey(phi.Result.Id);
                bool mapped = plan.ValueClass.TryGetValue(phi.Result.Id, out int classId);
                if (needed != mapped)
                {
                    errors.Add($"B{block.Id} phi %{phi.Result.Id} needed={needed} "
                        + $"mapped={mapped}");
                    continue;
                }
                if (!needed)
                    continue;
                if (!perBlockClass.Add((block.Id, classId)))
                    errors.Add($"B{block.Id} has two needed phis in C{classId}");
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp))
                {
                    if (plan.DeadCode.ConstantReplacements.ContainsKey(input.ValueId))
                        continue;
                    if (!plan.ValueClass.TryGetValue(input.ValueId, out int inputClass)
                        || inputClass != classId)
                        errors.Add($"B{block.Id} phi %{phi.Result.Id} input %{input.ValueId} "
                            + $"is not in C{classId}");
                }
            }
        }
    }

    private static void VerifyBlockPlans(
        SsaPhiLoweringPlan plan,
        IReadOnlyList<SsaBlock> executable,
        List<string> errors)
    {
        foreach (var block in executable)
        {
            if (!plan.Blocks.TryGetValue(block.Id, out var blockPlan))
                continue;
            var live = block.Instructions.Where(instruction =>
                plan.DeadCode.LiveInstructionIds.Contains(instruction.Id)).ToArray();
            var liveIds = live.Select(instruction => instruction.Id).ToHashSet();
            foreach (int planned in blockPlan.PlannedInstructionIds)
                if (!liveIds.Contains(planned))
                    errors.Add($"B{block.Id} schedules non-live I{planned}");
            if (blockPlan.PlannedInstructionIds.Count
                != blockPlan.PlannedInstructionIds.Distinct().Count())
                errors.Add($"B{block.Id} schedules an instruction twice");

            var effects = live.Where(instruction =>
                    !SemanticEffectClassifier.IsRemovableIfUnused(instruction.Operation))
                .Select(instruction => instruction.Id).ToArray();
            var scheduledEffects = blockPlan.PlannedInstructionIds
                .Where(id => effects.Contains(id)).ToArray();
            if (!effects.SequenceEqual(scheduledEffects))
                errors.Add($"B{block.Id} reorders observable effects");

            foreach (var root in blockPlan.Roots)
            {
                if (root.SpillValueId is { } spill && !plan.SpillTypes.ContainsKey(spill))
                    errors.Add($"B{block.Id} spills %{spill} without a type");
                if (root.ClassId is { } classId
                    && plan.Classes.All(item => item.Id != classId))
                    errors.Add($"B{block.Id} stores into unknown C{classId}");
                if (root.SpillValueId is not null && root.ClassId is not null)
                    errors.Add($"B{block.Id} root I{root.InstructionId} has two destinations");
            }
            if (blockPlan.Roots.Select(root => root.Ordinal).ToArray()
                is { Length: > 1 } ordinals
                && ordinals.Zip(ordinals.Skip(1)).Any(pair => pair.First >= pair.Second))
                errors.Add($"B{block.Id} roots are not in ordinal order");
        }
    }

    /// <summary>
    /// Independently replays slot contents along the block's own program order and checks that every
    /// phi input a successor reads is exactly what the slot holds when the block exits.
    /// </summary>
    private static void VerifySlotContents(
        SsaPhiLoweringPlan plan,
        IReadOnlyList<SsaBlock> executable,
        SccpResult sccp,
        List<string> errors)
    {
        var graph = plan.DeadCode.Sccp.Graph;
        var byId = executable.SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);

        // A class seeded by an initial local or argument already holds that value on method entry,
        // whether it reuses the original slot or receives an explicit entry copy.
        var entrySlots = new Dictionary<int, int>();
        foreach (var phiClass in plan.Classes)
        {
            int? initial = phiClass.Members
                .Where(member => graph.Value(member).Kind
                    is SsaValueKind.InitialLocal or SsaValueKind.InitialArgument)
                .Select(member => (int?)member).FirstOrDefault();
            if (initial is { } value)
                entrySlots[phiClass.Id] = value;
        }
        foreach (var store in plan.EntryStores)
        {
            if (entrySlots.TryGetValue(store.ClassId, out int seeded) && seeded != store.ValueId)
                errors.Add($"entry store for C{store.ClassId} writes %{store.ValueId} "
                    + $"but the class is seeded by %{seeded}");
            entrySlots[store.ClassId] = store.ValueId;
        }

        foreach (var block in executable)
        {
            if (!plan.Blocks.TryGetValue(block.Id, out var blockPlan))
                continue;
            var slot = new Dictionary<int, int>();
            if (block.Id == 0)
                foreach (var pair in entrySlots)
                    slot[pair.Key] = pair.Value;
            foreach (var phi in block.Phis)
                if (plan.ValueClass.TryGetValue(phi.Result.Id, out int entryClass))
                    slot[entryClass] = phi.Result.Id;
            foreach (var root in blockPlan.Roots.Where(root => root.ClassId is not null))
                slot[root.ClassId!.Value] = byId[root.InstructionId].Outputs[0];
            foreach (var store in blockPlan.ExitStores)
                slot[store.ClassId] = store.ValueId;

            foreach (var phi in executable.SelectMany(target => target.Phis))
            {
                if (!plan.ValueClass.TryGetValue(phi.Result.Id, out int classId))
                    continue;
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp)
                    .Where(input => input.PredecessorBlockId == block.Id
                        || block.Id == 0 && input.Kind == SsaPhiInputKind.MethodEntry))
                {
                    if (block.Id == 0 && input.Kind == SsaPhiInputKind.MethodEntry)
                    {
                        if (plan.ValueClass.GetValueOrDefault(input.ValueId, -1) != classId)
                            errors.Add($"entry input %{input.ValueId} of B0 phi "
                                + $"%{phi.Result.Id} is not in C{classId}");
                        continue;
                    }
                    if (!slot.TryGetValue(classId, out int actual) || actual != input.ValueId)
                        errors.Add($"B{block.Id} exits with C{classId}="
                            + (slot.TryGetValue(classId, out int held) ? $"%{held}" : "nothing")
                            + $" but B{phi.Result.DefinitionBlockId} reads %{input.ValueId}");
                }
            }
        }
    }
}

