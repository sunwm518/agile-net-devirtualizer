namespace AgileDevirtualizer.Analysis;

internal enum SccpValueKind
{
    Undefined,
    Constant,
    Overdefined,
}

internal readonly record struct SccpValue(
    SccpValueKind Kind,
    object? Constant = null)
{
    public static SccpValue Undefined { get; } = new(SccpValueKind.Undefined);
    public static SccpValue Overdefined { get; } = new(SccpValueKind.Overdefined);

    public static SccpValue FromConstant(object? value) =>
        new(SccpValueKind.Constant, value);

    public static SccpValue Join(SccpValue current, SccpValue incoming)
    {
        if (current.Kind == SccpValueKind.Undefined)
            return incoming;
        if (incoming.Kind == SccpValueKind.Undefined)
            return current;
        if (current.Kind == SccpValueKind.Overdefined
            || incoming.Kind == SccpValueKind.Overdefined)
            return Overdefined;
        return ConstantsEqual(current.Constant, incoming.Constant)
            ? current : Overdefined;
    }

    private static bool ConstantsEqual(object? left, object? right)
    {
        if (left is float leftFloat && right is float rightFloat)
            return BitConverter.SingleToInt32Bits(leftFloat)
                == BitConverter.SingleToInt32Bits(rightFloat);
        if (left is double leftDouble && right is double rightDouble)
            return BitConverter.DoubleToInt64Bits(leftDouble)
                == BitConverter.DoubleToInt64Bits(rightDouble);
        return Equals(left, right);
    }

    public override string ToString() => Kind == SccpValueKind.Constant
        ? $"const({Constant ?? "null"})" : Kind.ToString();
}

internal sealed record SccpStatistics(
    int ExecutableBlocks,
    int ExecutableEdges,
    int InfeasibleNormalEdges,
    int Constants,
    int Overdefined,
    int Undefined,
    int FoldedTerminators,
    int FoldedPureCalls);

internal sealed class SccpResult
{
    public SccpResult(
        SsaGraph graph,
        IReadOnlyDictionary<int, SccpValue> values,
        IReadOnlySet<int> executableBlocks,
        IReadOnlySet<ControlFlowEdge> executableEdges,
        bool converged,
        int iterations,
        int foldedPureCalls)
    {
        Graph = graph;
        Values = values;
        ExecutableBlocks = executableBlocks;
        ExecutableEdges = executableEdges;
        Converged = converged;
        Iterations = iterations;
        FoldedPureCalls = foldedPureCalls;
    }

    public SsaGraph Graph { get; }
    public IReadOnlyDictionary<int, SccpValue> Values { get; }
    public IReadOnlySet<int> ExecutableBlocks { get; }
    public IReadOnlySet<ControlFlowEdge> ExecutableEdges { get; }
    public bool Converged { get; }
    public int Iterations { get; }
    public int FoldedPureCalls { get; }
}
