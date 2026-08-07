namespace AgileDevirtualizer.Analysis;

internal sealed record SsaEdgeCopyVerification(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;

    public override string ToString() => Valid ? "valid"
        : "invalid: " + string.Join(" | ", Errors.Take(5));
}

/// <summary>Independently verifies typed phi coverage, placement and critical-edge splitting.</summary>
internal static class SsaEdgeCopyVerifier
{
    public static SsaEdgeCopyVerification Verify(SsaEdgeCopyPlan plan)
    {
        if (!plan.Eligible)
            return new SsaEdgeCopyVerification([$"plan is not eligible: {plan.Reason}"]);
        var errors = new List<string>();
        var graph = plan.DeadCode.Sccp.Graph;
        var sccp = plan.DeadCode.Sccp;
        var expected = new HashSet<(ControlFlowEdge? Edge, int Phi, int Source)>();
        foreach (var block in graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)))
        {
            foreach (var phi in block.Phis.Where(phi =>
                plan.DeadCode.LiveValueIds.Contains(phi.Result.Id)
                && !plan.DeadCode.ConstantReplacements.ContainsKey(phi.Result.Id)))
            {
                if (!plan.PhiTypes.ContainsKey(phi.Result.Id))
                    errors.Add($"live phi %{phi.Result.Id} has no typed destination");
                foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp))
                {
                    if (input.Kind == SsaPhiInputKind.MethodEntry)
                    {
                        expected.Add((null, phi.Result.Id, input.ValueId));
                        continue;
                    }
                    foreach (var edge in sccp.ExecutableEdges.Where(edge =>
                        edge.SourceBlockId == input.PredecessorBlockId
                        && edge.TargetBlockId == block.Id
                        && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)))
                        expected.Add((edge, phi.Result.Id, input.ValueId));
                }
            }
        }

        var actual = new HashSet<(ControlFlowEdge? Edge, int Phi, int Source)>();
        foreach (var edgePlan in plan.EdgeCopies)
        {
            if (edgePlan.Copies.Select(copy => copy.PhiValueId).Distinct().Count()
                != edgePlan.Copies.Count)
                errors.Add($"edge {Display(edgePlan.Edge)} writes one phi more than once");
            foreach (var copy in edgePlan.Copies)
            {
                actual.Add((edgePlan.Edge, copy.PhiValueId, copy.SourceValueId));
                if (!plan.PhiTypes.TryGetValue(copy.PhiValueId, out var type)
                    || type.FullName != copy.Type.FullName)
                    errors.Add($"copy %{copy.SourceValueId}->%{copy.PhiValueId} has wrong type");
            }
            if (edgePlan.Edge is not { } edge)
            {
                if (edgePlan.Placement != SsaEdgeCopyPlacement.MethodEntry)
                    errors.Add("edge-less copies are not placed at method entry");
                continue;
            }
            int outgoing = NormalOutgoing(sccp, edge.SourceBlockId);
            int incoming = NormalIncoming(sccp, edge.TargetBlockId);
            var required = outgoing > 1 && incoming > 1
                ? SsaEdgeCopyPlacement.SplitBlock
                : outgoing == 1
                    ? SsaEdgeCopyPlacement.SourceExit
                    : SsaEdgeCopyPlacement.TargetEntry;
            if (edgePlan.Placement != required)
                errors.Add($"edge {Display(edge)} uses {edgePlan.Placement}, expected {required}");
        }

        foreach (var missing in expected.Except(actual))
            errors.Add($"missing copy %{missing.Source}->%{missing.Phi} on {Display(missing.Edge)}");
        foreach (var extra in actual.Except(expected))
            errors.Add($"extra copy %{extra.Source}->%{extra.Phi} on {Display(extra.Edge)}");

        foreach (var instruction in graph.Blocks.Where(block => block.Reachable
                && sccp.ExecutableBlocks.Contains(block.Id))
            .SelectMany(block => block.Instructions)
            .Where(instruction => plan.DeadCode.LiveInstructionIds.Contains(instruction.Id)))
        {
            foreach (int output in instruction.Outputs.Where(output =>
                !plan.DeadCode.ConstantReplacements.ContainsKey(output)))
                if (!plan.OperationSpillTypes.ContainsKey(output))
                    errors.Add($"live operation output %{output} has no typed spill");
        }
        return new SsaEdgeCopyVerification(errors);
    }

    private static int NormalOutgoing(SccpResult sccp, int blockId) =>
        sccp.ExecutableEdges.Count(edge => edge.SourceBlockId == blockId
            && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));

    private static int NormalIncoming(SccpResult sccp, int blockId) =>
        sccp.ExecutableEdges.Count(edge => edge.TargetBlockId == blockId
            && !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));

    private static string Display(ControlFlowEdge? edge) => edge is null
        ? "entry"
        : $"B{edge.SourceBlockId}->B{edge.TargetBlockId}:{edge.Kind}"
            + (edge.SwitchCaseIndex is { } index ? $"[{index}]" : string.Empty);
}
