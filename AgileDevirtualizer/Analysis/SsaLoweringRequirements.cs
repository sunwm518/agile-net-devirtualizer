namespace AgileDevirtualizer.Analysis;

[Flags]
internal enum SsaLoweringFeature
{
    None = 0,
    MultipleBlocks = 1 << 0,
    VariablePhi = 1 << 1,
    EvaluationStackPhi = 1 << 2,
    CriticalEdge = 1 << 3,
    ExceptionRegion = 1 << 4,
    ExceptionObject = 1 << 5,
    ManagedPointer = 1 << 6,
    AddressOperation = 1 << 7,
    Prefix = 1 << 8,
    MultiUseValue = 1 << 9,
    UnknownValueType = 1 << 10,
}

internal sealed record SsaLoweringRequirements(
    SsaLoweringFeature Features,
    int ExecutableBlocks,
    int VariablePhis,
    int EvaluationStackPhis,
    int CriticalEdges,
    int MultiUseValues,
    int UnknownValueTypes)
{
    public bool StraightLineCandidate => (Features & ~(
        SsaLoweringFeature.MultiUseValue | SsaLoweringFeature.UnknownValueType)) ==
        SsaLoweringFeature.None;

    public bool ExactStraightLineCandidate => Features == SsaLoweringFeature.None;

    /// <summary>
    /// Multi-block methods whose only extra requirement over straight-line lowering is phi
    /// resolution. Exception regions, exception entry objects, managed pointers, address
    /// operations and prefixes stay on the lossless route until each is modelled explicitly.
    /// </summary>
    public bool PhiLoweringCandidate => (Features & ~(
        SsaLoweringFeature.MultipleBlocks | SsaLoweringFeature.VariablePhi
        | SsaLoweringFeature.EvaluationStackPhi | SsaLoweringFeature.CriticalEdge
        | SsaLoweringFeature.MultiUseValue | SsaLoweringFeature.UnknownValueType)) ==
        SsaLoweringFeature.None;
}

internal static class SsaLoweringRequirementAnalyzer
{
    public static SsaLoweringRequirements Analyze(SccpResult sccp)
    {
        var graph = sccp.Graph;
        var executable = graph.Blocks.Where(block => block.Reachable
            && sccp.ExecutableBlocks.Contains(block.Id)).ToArray();
        var executableIds = executable.Select(block => block.Id).ToHashSet();
        int variablePhis = executable.Sum(block => block.Phis.Count(phi =>
            phi.LocationKind == SsaPhiLocationKind.Variable));
        int stackPhis = executable.Sum(block => block.Phis.Count(phi =>
            phi.LocationKind == SsaPhiLocationKind.EvaluationStack));
        int criticalEdges = sccp.ExecutableEdges.Count(edge =>
            !ControlFlowSimplifier.IsExceptionEdge(edge.Kind)
            && NormalDegree(graph, edge.SourceBlockId, outgoing: true) > 1
            && NormalDegree(graph, edge.TargetBlockId, outgoing: false) > 1);
        var operationOutputs = executable.SelectMany(block => block.Instructions)
            .SelectMany(instruction => instruction.Outputs).ToHashSet();
        int multiUse = operationOutputs.Count(valueId => graph.Uses.Count(use =>
            use.ValueId == valueId && IsExecutableUse(use, executableIds)) > 1);
        int unknownTypes = operationOutputs.Count(valueId =>
            graph.Value(valueId).AbstractValue.Kind == AbstractValueKind.Unknown);

        SsaLoweringFeature features = SsaLoweringFeature.None;
        if (executable.Length > 1) features |= SsaLoweringFeature.MultipleBlocks;
        if (variablePhis > 0) features |= SsaLoweringFeature.VariablePhi;
        if (stackPhis > 0) features |= SsaLoweringFeature.EvaluationStackPhi;
        if (criticalEdges > 0) features |= SsaLoweringFeature.CriticalEdge;
        if (graph.Source.ExceptionRegions.Count > 0) features |= SsaLoweringFeature.ExceptionRegion;
        if (graph.Values.Any(value => value.Kind == SsaValueKind.ExceptionObject))
            features |= SsaLoweringFeature.ExceptionObject;
        if (graph.Values.Any(value => value.AbstractValue.Kind == AbstractValueKind.ManagedPointer))
            features |= SsaLoweringFeature.ManagedPointer;
        if (executable.SelectMany(block => block.Instructions).Any(instruction =>
            instruction.Operation.Code is SemanticOperationCode.LoadArgumentAddress
                or SemanticOperationCode.LoadLocalAddress
                or SemanticOperationCode.LoadElementAddress))
            features |= SsaLoweringFeature.AddressOperation;
        if (executable.SelectMany(block => block.Instructions).Any(instruction =>
            instruction.Operation.Code == SemanticOperationCode.Prefix))
            features |= SsaLoweringFeature.Prefix;
        if (multiUse > 0) features |= SsaLoweringFeature.MultiUseValue;
        if (unknownTypes > 0) features |= SsaLoweringFeature.UnknownValueType;

        return new SsaLoweringRequirements(features, executable.Length, variablePhis,
            stackPhis, criticalEdges, multiUse, unknownTypes);
    }

    private static int NormalDegree(SsaGraph graph, int blockId, bool outgoing)
    {
        var block = graph.Source.Blocks[blockId];
        var edges = outgoing
            ? SsaControlFlow.Outgoing(graph.Source, block)
            : SsaControlFlow.Incoming(graph.Source, block);
        return edges.Count(edge => !ControlFlowSimplifier.IsExceptionEdge(edge.Kind));
    }

    private static bool IsExecutableUse(SsaUse use, IReadOnlySet<int> executableIds) =>
        executableIds.Contains(use.BlockId);
}
