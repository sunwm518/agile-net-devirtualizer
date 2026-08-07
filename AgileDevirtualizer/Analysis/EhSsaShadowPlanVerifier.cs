namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaShadowPlanVerification(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class EhSsaShadowPlanVerifier
{
    public static EhSsaShadowPlanVerification Verify(EhSsaShadowPlan plan)
    {
        if (!plan.Eligible)
            return new EhSsaShadowPlanVerification([$"plan rejected: {plan.Reason}"]);
        var errors = new List<string>();
        var graph = plan.DeadCode.Sccp.Graph;
        if (plan.BlockOrder.Distinct().Count() != plan.BlockOrder.Count)
            errors.Add("block order contains duplicates");
        if (!plan.BlockOrder.Select(id => graph.Source.Blocks[id].StartInstructionIndex)
            .SequenceEqual(plan.BlockOrder.Select(id =>
                graph.Source.Blocks[id].StartInstructionIndex).Order()))
            errors.Add("EH block order is not lexical");
        foreach (var block in graph.Blocks.Where(block => plan.BlockOrder.Contains(block.Id)))
        foreach (var phi in block.Phis.Where(phi =>
            plan.EmissionValueIds.Contains(phi.Result.Id)
            && !plan.ConstantValues.ContainsKey(phi.Result.Id)))
        {
            if (phi.LocationKind == SsaPhiLocationKind.Variable)
            {
                if (!plan.VariablePhiSlots.TryGetValue(phi.Result.Id, out var slot)
                    || slot != phi.Variable)
                    errors.Add($"variable phi %{phi.Result.Id} does not reuse {phi.Variable}");
            }
            else if (!plan.StackPhiTypes.ContainsKey(phi.Result.Id))
                errors.Add($"stack phi %{phi.Result.Id} has no typed local");
        }
        foreach (var entry in plan.Entries.Entries.Where(entry =>
            plan.BlockOrder.Contains(entry.BlockId) && entry.ExceptionObject is not null))
        {
            if (entry.ExceptionObject!.SsaValueId is not { } valueId
                || !plan.ExceptionObjectTypes.ContainsKey(valueId))
                errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} has no exception spill");
        }
        foreach (var copyPlan in plan.EdgeCopies)
        {
            if (copyPlan.Placement == SsaEdgeCopyPlacement.SplitBlock)
                errors.Add("initial EH shadow plan contains a split block");
            foreach (var copy in copyPlan.Copies)
                if (!plan.StackPhiTypes.TryGetValue(copy.PhiValueId, out var type)
                    || type.FullName != copy.Type.FullName)
                    errors.Add($"copy to %{copy.PhiValueId} has wrong destination type");
        }
        foreach (var pair in plan.FunctionPointers)
        {
            int valueId = pair.Key;
            var rematerialization = pair.Value;
            if (valueId != rematerialization.ValueId)
                errors.Add($"function-pointer map key %{valueId} does not match its value");
            if (plan.OperationSpillTypes.ContainsKey(valueId))
                errors.Add($"function pointer %{valueId} also has an invalid local spill");
            if (!plan.EmissionInstructionIds.Contains(
                    rematerialization.DefinitionInstructionId)
                || !plan.EmissionInstructionIds.Contains(
                    rematerialization.ConsumerInstructionId))
                errors.Add($"function pointer %{valueId} references a non-emitted instruction");
            if (rematerialization.Operation.Code
                    != SemanticOperationCode.LoadFunctionPointer
                || rematerialization.Operation.Semantics.Dispatch
                    != SemanticDispatchKind.Direct)
                errors.Add($"function pointer %{valueId} is not an exact direct ldftn");
        }
        foreach (var instruction in graph.Blocks.Where(block => plan.BlockOrder.Contains(block.Id))
            .SelectMany(block => block.Instructions)
            .Where(instruction => plan.EmissionInstructionIds.Contains(instruction.Id)))
        foreach (int output in instruction.Outputs.Where(output =>
            plan.EmissionValueIds.Contains(output)
            && !plan.ConstantValues.ContainsKey(output)))
            if (!plan.OperationSpillTypes.ContainsKey(output)
                && !plan.FunctionPointers.ContainsKey(output))
                errors.Add($"live operation output %{output} has no spill");
        foreach (var store in graph.Blocks.Where(block => plan.BlockOrder.Contains(block.Id))
            .SelectMany(block => block.Instructions)
            .Where(instruction => SsaStackSemantics.ForOperation(instruction.Operation).Behavior
                == SsaOperationBehavior.StoreVariable))
            if (!plan.EmissionInstructionIds.Contains(store.Id))
                errors.Add($"source-variable store I{store.Id} is absent from EH emission");
        return new EhSsaShadowPlanVerification(errors);
    }
}
