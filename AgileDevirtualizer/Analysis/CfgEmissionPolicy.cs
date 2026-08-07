namespace AgileDevirtualizer.Analysis;

[Flags]
internal enum CfgControlFlowFeatures
{
    None = 0,
    ExceptionRegions = 1,
    Leave = 2,
    Switch = 4,
    BackEdge = 8,
    MergePoint = 16,
    StraightLine = 32,
}

internal sealed record CfgEmissionEligibility(
    bool Candidate,
    bool Eligible,
    CfgControlFlowFeatures Features,
    string Reason);

/// <summary>Selects CFG-emission candidates only from formal graph properties.</summary>
internal static class CfgEmissionPolicy
{
    public static CfgEmissionEligibility Evaluate(
        SemanticControlFlowGraph graph,
        IReadOnlyList<string> graphErrors,
        WorklistAnalysisResult analysis)
    {
        var features = DetectFeatures(graph);
        if (graphErrors.Count > 0)
            return new CfgEmissionEligibility(true, false, features,
                "invalid CFG: " + string.Join("; ", graphErrors));
        if (!analysis.Converged)
            return new CfgEmissionEligibility(true, false, features,
                "worklist did not converge");
        if (analysis.Blocks.Values.Any(block => block.Entry.Stack is null))
            return new CfgEmissionEligibility(true, false, features,
                "worklist has a conflicting entry stack shape");
        if (graph.Blocks.SelectMany(block => block.Operations)
            .Any(operation => !SemanticCilLowerer.CanLower(operation)))
        {
            return new CfgEmissionEligibility(true, false, features,
                "semantic operation has no independent CIL lowering");
        }
        if (graph.Blocks.Any(block =>
            block.Terminator.Kind != SemanticTerminatorKind.FallThrough
            && !SemanticCilLowerer.CanLower(block.Terminator)))
        {
            return new CfgEmissionEligibility(true, false, features,
                "semantic terminator has no independent CIL lowering");
        }
        return new CfgEmissionEligibility(true, true, features, "eligible");
    }

    internal static CfgControlFlowFeatures DetectFeatures(SemanticControlFlowGraph graph)
    {
        var features = CfgControlFlowFeatures.None;
        if (graph.ExceptionRegions.Count > 0)
            features |= CfgControlFlowFeatures.ExceptionRegions;
        if (graph.Edges.Any(edge => edge.Kind == ControlFlowEdgeKind.Leave))
            features |= CfgControlFlowFeatures.Leave;
        if (graph.Blocks.Any(block => block.Terminator.Kind == SemanticTerminatorKind.Switch))
            features |= CfgControlFlowFeatures.Switch;

        var normalEdges = graph.Edges.Where(edge => !IsExceptionEdge(edge.Kind)).ToArray();
        if (normalEdges.Any(edge =>
            graph.Blocks[edge.TargetBlockId].StartInstructionIndex
            <= graph.Blocks[edge.SourceBlockId].StartInstructionIndex))
        {
            features |= CfgControlFlowFeatures.BackEdge;
        }
        if (graph.Blocks.Any(block => normalEdges
            .Where(edge => edge.TargetBlockId == block.Id)
            .Select(edge => edge.SourceBlockId)
            .Distinct()
            .Take(2)
            .Count() == 2))
        {
            features |= CfgControlFlowFeatures.MergePoint;
        }
        if (features == CfgControlFlowFeatures.None)
            features = CfgControlFlowFeatures.StraightLine;
        return features;
    }

    private static bool IsExceptionEdge(ControlFlowEdgeKind kind) =>
        ControlFlowEdgeSemantics.IsException(kind);
}
