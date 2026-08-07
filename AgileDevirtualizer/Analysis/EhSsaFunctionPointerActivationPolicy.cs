namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Runtime-proven gate for direct function pointers that are rematerialized immediately at their
/// sole delegate/native-int constructor. Any receiver, phi, multi-use or cross-block form has
/// already been rejected by the shadow model and remains ineligible here.
/// </summary>
internal static class EhSsaFunctionPointerActivationPolicy
{
    public static EhSsaActivationEligibility Evaluate(EhSsaShadowPlan plan)
    {
        if (!plan.Eligible)
            return Reject(plan.Reason);
        if (plan.FunctionPointers.Count == 0)
            return Reject("method has no function-pointer rematerializations");
        if (plan.TotalCopies != 0)
            return Reject("combined function-pointer and EH edge-copy lowering is not runtime-proven");
        var unsupported = plan.DeadCode.Sccp.Graph.Source.ExceptionRegions
            .Select(region => region.ClauseKind).Distinct()
            .Where(kind => kind is not ExceptionClauseKind.Catch
                and not ExceptionClauseKind.Finally).ToArray();
        if (unsupported.Length != 0)
            return Reject("EH clause kinds remain shadow-only: "
                + string.Join(", ", unsupported));
        if (plan.Continuations.EndFilters.Count != 0)
            return Reject("endfilter remains shadow-only");

        var instructions = plan.DeadCode.Sccp.Graph.Blocks
            .SelectMany(block => block.Instructions)
            .ToDictionary(instruction => instruction.Id);
        foreach (var pointer in plan.FunctionPointers.Values)
        {
            if (!instructions.TryGetValue(pointer.DefinitionInstructionId, out var definition)
                || !instructions.TryGetValue(pointer.ConsumerInstructionId, out var consumer)
                || definition.BlockId != consumer.BlockId
                || consumer.Ordinal != definition.Ordinal + 1
                || definition.Operation.Code != SemanticOperationCode.LoadFunctionPointer
                || definition.Operation.Semantics.Dispatch != SemanticDispatchKind.Direct
                || consumer.Operation.Code != SemanticOperationCode.NewObject
                || pointer.ConsumerInputIndex < 0
                || pointer.ConsumerInputIndex >= consumer.Inputs.Count
                || consumer.Inputs[pointer.ConsumerInputIndex] != pointer.ValueId)
                return Reject($"function pointer %{pointer.ValueId} lost its adjacent direct shape");
        }

        return new EhSsaActivationEligibility(true,
            "runtime-proven adjacent direct function-pointer rematerialization");

        static EhSsaActivationEligibility Reject(string reason) => new(false, reason);
    }
}
