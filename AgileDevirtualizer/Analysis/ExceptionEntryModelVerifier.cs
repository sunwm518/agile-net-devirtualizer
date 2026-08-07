namespace AgileDevirtualizer.Analysis;

internal sealed record ExceptionEntryVerificationResult(IReadOnlyList<string> Errors)
{
    public bool IsValid => Errors.Count == 0;
}

/// <summary>Independent invariant checks for CLI-created handler-entry state.</summary>
internal static class ExceptionEntryModelVerifier
{
    public static ExceptionEntryVerificationResult Verify(ExceptionEntryModel model)
    {
        var errors = new List<string>();
        var graph = model.Graph;
        VerifyEntryInventory(model, errors);
        foreach (var entry in model.Entries)
            VerifyEntry(graph, entry, errors);
        return new ExceptionEntryVerificationResult(errors);
    }

    private static void VerifyEntryInventory(ExceptionEntryModel model, List<string> errors)
    {
        foreach (var region in model.Graph.Source.ExceptionRegions)
        {
            var entries = model.Entries.Where(entry =>
                entry.ExceptionRegionId == region.Id).ToArray();
            int expected = region.ClauseKind == ExceptionClauseKind.Filter ? 2
                : region.ClauseKind == ExceptionClauseKind.Unknown ? 0 : 1;
            if (entries.Length != expected)
                errors.Add($"EH{region.Id} {region.ClauseKind} has {entries.Length} entries, expected {expected}");
            if (region.ClauseKind == ExceptionClauseKind.Catch
                && entries.SingleOrDefault()?.ExceptionObject?.StaticType is null)
                errors.Add($"EH{region.Id} catch type token is missing or unresolved");
            if (region.ClauseKind == ExceptionClauseKind.Filter)
            {
                if (region.FilterStart is not { } filterStart)
                    errors.Add($"EH{region.Id} filter has no filter-start index");
                else if (filterStart >= region.HandlerStart)
                    errors.Add($"EH{region.Id} filter start {filterStart} does not precede handler start {region.HandlerStart}");
            }
        }

        foreach (var duplicate in model.Entries.GroupBy(entry =>
            (entry.ExceptionRegionId, entry.Kind)).Where(group => group.Count() != 1))
            errors.Add($"EH{duplicate.Key.ExceptionRegionId} has duplicate {duplicate.Key.Kind} entries");
    }

    private static void VerifyEntry(
        SsaGraph graph,
        ExceptionEntry entry,
        List<string> errors)
    {
        var source = graph.Source;
        var block = source.Blocks[entry.BlockId];
        var ssaBlock = graph.Blocks[entry.BlockId];
        if (block.StartInstructionIndex != entry.InstructionIndex)
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} enters inside B{entry.BlockId}");

        RegionZone expectedZone = entry.Kind == ExceptionEntryKind.FilterEvaluation
            ? RegionZone.Filter : RegionZone.Handler;
        if (!entry.RegionPath.Frames.Any(frame =>
            frame.RegionId == entry.ExceptionRegionId && frame.Zone == expectedZone))
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} has wrong RegionPath {entry.RegionPath}");

        var incoming = source.Incoming(block).Where(edge =>
            edge.ExceptionRegionId == entry.ExceptionRegionId
            && edge.Kind == entry.IncomingEdgeKind).ToArray();
        if (incoming.Length == 0)
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} has no {entry.IncomingEdgeKind} edge");

        if (entry.Kind == ExceptionEntryKind.FilterEvaluation)
        {
            var endFilters = source.Blocks.Where(candidate => candidate.RegionPath.Frames.Any(frame =>
                    frame.RegionId == entry.ExceptionRegionId && frame.Zone == RegionZone.Filter))
                .Where(candidate => candidate.Terminator.Kind == SemanticTerminatorKind.EndFilter)
                .ToArray();
            if (endFilters.Length != 1)
                errors.Add($"EH{entry.ExceptionRegionId} filter has {endFilters.Length} endfilter terminators");
        }

        if (ssaBlock.EntryStack.Count != entry.ExpectedStackDepth)
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} SSA entry stack has "
                + $"{ssaBlock.EntryStack.Count}, expected {entry.ExpectedStackDepth}");
        if (entry.ExceptionObject is null)
            return;
        if (entry.ExceptionObject.StaticType is null)
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} has no static exception-object type");
        if (!ssaBlock.Reachable)
            return;
        if (entry.ExceptionObject.SsaValueId is not { } valueId)
        {
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} has no SSA exception object");
            return;
        }

        var value = graph.Value(valueId);
        if (value.Kind != SsaValueKind.ExceptionObject
            || value.DefinitionBlockId != entry.BlockId || value.StackSlot != 0)
            errors.Add($"%{valueId} is not the entry exception object for B{entry.BlockId}");
        if (value.AbstractValue.Kind != AbstractValueKind.Reference
            || value.AbstractValue.Nullability != AbstractNullability.NonNull)
            errors.Add($"%{valueId} is not a non-null reference");
        if (ssaBlock.Phis.Any(phi => phi.LocationKind == SsaPhiLocationKind.EvaluationStack))
            errors.Add($"EH{entry.ExceptionRegionId} {entry.Kind} incorrectly merges its CLI-created stack through phi");
    }
}
