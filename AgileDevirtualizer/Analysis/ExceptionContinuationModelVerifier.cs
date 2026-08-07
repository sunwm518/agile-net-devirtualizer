namespace AgileDevirtualizer.Analysis;

internal sealed record ExceptionContinuationVerification(IReadOnlyList<string> Errors)
{
    public bool Valid => Errors.Count == 0;
}

internal static class ExceptionContinuationModelVerifier
{
    public static ExceptionContinuationVerification Verify(ExceptionContinuationModel model)
    {
        var errors = new List<string>();
        VerifyInventory(model, errors);
        foreach (var leave in model.Leaves) VerifyLeave(model, leave, errors);
        foreach (var rethrow in model.Rethrows) VerifyRethrow(model, rethrow, errors);
        foreach (var endFinally in model.EndFinallys)
            VerifyEndFinally(model, endFinally, errors);
        foreach (var endFilter in model.EndFilters) VerifyEndFilter(model, endFilter, errors);
        return new ExceptionContinuationVerification(errors);
    }

    private static void VerifyInventory(
        ExceptionContinuationModel model,
        List<string> errors)
    {
        var graph = model.Graph;
        int leaves = graph.Source.Edges.Count(edge => edge.Kind == ControlFlowEdgeKind.Leave
            && graph.Blocks[edge.SourceBlockId].Reachable);
        int rethrows = graph.Blocks.Count(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.Rethrow);
        int endFinallys = graph.Blocks.Count(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.EndFinally);
        int endFilters = graph.Blocks.Count(block => block.Reachable
            && block.Terminator?.Terminator.Kind == SemanticTerminatorKind.EndFilter);
        if (model.Leaves.Count != leaves) errors.Add($"leave inventory {model.Leaves.Count}!={leaves}");
        if (model.Rethrows.Count != rethrows) errors.Add($"rethrow inventory {model.Rethrows.Count}!={rethrows}");
        if (model.EndFinallys.Count != endFinallys)
            errors.Add($"endfinally inventory {model.EndFinallys.Count}!={endFinallys}");
        if (model.EndFilters.Count != endFilters)
            errors.Add($"endfilter inventory {model.EndFilters.Count}!={endFilters}");
        if (model.Leaves.Select(leave => leave.Id).Distinct().Count() != model.Leaves.Count)
            errors.Add("leave continuation ids are not unique");
    }

    private static void VerifyLeave(
        ExceptionContinuationModel model,
        LeaveContinuation leave,
        List<string> errors)
    {
        if (!leave.Transition.Valid)
            errors.Add($"leave L{leave.Id} is invalid: {leave.Transition.Reason}");
        if (leave.Edge.TargetBlockId != leave.FinalTargetBlockId)
            errors.Add($"leave L{leave.Id} final target changed");
        var source = model.Graph.Source.Blocks[leave.Edge.SourceBlockId].RegionPath;
        var target = model.Graph.Source.Blocks[leave.Edge.TargetBlockId].RegionPath;
        var expected = source.Frames.Where(frame => frame.Zone == RegionZone.Try
                && frame.ClauseKind == ExceptionClauseKind.Finally
                && !target.Frames.Contains(frame))
            .Reverse().Select(frame => frame.RegionId).Distinct().ToArray();
        if (!leave.FinallyRegionIds.SequenceEqual(expected))
            errors.Add($"leave L{leave.Id} finally order differs from RegionPath");
        foreach (int regionId in leave.FinallyRegionIds)
        {
            var region = model.Graph.Source.ExceptionRegions.SingleOrDefault(region =>
                region.Id == regionId);
            if (region?.ClauseKind != ExceptionClauseKind.Finally)
                errors.Add($"leave L{leave.Id} references non-finally EH{regionId}");
        }
    }

    private static void VerifyRethrow(
        ExceptionContinuationModel model,
        RethrowContinuation rethrow,
        List<string> errors)
    {
        var block = model.Graph.Blocks[rethrow.SourceBlockId];
        if (rethrow.ActiveCatchRegionId is null)
            errors.Add($"B{block.Id} rethrow has no enclosing catch/filter handler");
        if (block.Terminator?.Inputs.Count != 0)
            errors.Add($"B{block.Id} rethrow consumes an SSA value");
        if (SsaControlFlow.Outgoing(model.Graph.Source,
            model.Graph.Source.Blocks[block.Id]).Any(edge =>
                !ControlFlowEdgeSemantics.IsException(edge.Kind)))
            errors.Add($"B{block.Id} rethrow has a normal CFG successor");
        if (!rethrow.ContinuesDynamicExceptionSearch)
            errors.Add($"B{block.Id} rethrow lacks dynamic exception search");
    }

    private static void VerifyEndFinally(
        ExceptionContinuationModel model,
        EndFinallyContinuation endFinally,
        List<string> errors)
    {
        var block = model.Graph.Blocks[endFinally.SourceBlockId];
        if (endFinally.HandlerRegionId is null
            || endFinally.HandlerKind is not (ExceptionClauseKind.Finally
                or ExceptionClauseKind.Fault))
            errors.Add($"B{block.Id} endfinally has no finally/fault owner");
        if (block.Terminator?.Inputs.Count != 0)
            errors.Add($"B{block.Id} endfinally consumes an SSA value");
        if (!endFinally.ContinuesExceptionUnwind)
            errors.Add($"B{block.Id} endfinally cannot continue exception unwind");
        foreach (int leaveId in endFinally.ResumableLeaveIds)
            if (!model.Leaves.Any(leave => leave.Id == leaveId
                && endFinally.HandlerRegionId is { } regionId
                && leave.FinallyRegionIds.Contains(regionId)))
                errors.Add($"B{block.Id} resumes unrelated leave L{leaveId}");
        if (endFinally.HandlerKind == ExceptionClauseKind.Fault
            && endFinally.ResumableLeaveIds.Count != 0)
            errors.Add($"B{block.Id} fault handler resumes normal leave");
    }

    private static void VerifyEndFilter(
        ExceptionContinuationModel model,
        EndFilterContinuation endFilter,
        List<string> errors)
    {
        var block = model.Graph.Blocks[endFilter.SourceBlockId];
        if (endFilter.FilterRegionId is null)
            errors.Add($"B{block.Id} endfilter has no filter owner");
        if (block.Terminator?.Inputs.Count != 1)
            errors.Add($"B{block.Id} endfilter does not consume exactly one SSA predicate");
        else if (model.Graph.Value(block.Terminator.Inputs[0]).AbstractValue.Kind
            != AbstractValueKind.Int32)
            errors.Add($"B{block.Id} endfilter predicate is not int32");
        if (endFilter.AcceptedHandlerBlockId is null)
            errors.Add($"B{block.Id} endfilter has no accepted-handler continuation");
        if (!endFilter.RejectedContinuesExceptionSearch)
            errors.Add($"B{block.Id} endfilter has no rejected-search continuation");
    }
}
