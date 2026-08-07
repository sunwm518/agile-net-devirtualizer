using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal enum SsaCilTypeKind
{
    Undefined,
    Exact,
    Null,
    Conflict,
}

internal readonly record struct SsaCilType(SsaCilTypeKind Kind, TypeSignature? Type = null)
{
    public static SsaCilType Undefined { get; } = new(SsaCilTypeKind.Undefined);
    public static SsaCilType Null { get; } = new(SsaCilTypeKind.Null);
    public static SsaCilType Conflict { get; } = new(SsaCilTypeKind.Conflict);

    public static SsaCilType Exact(TypeSignature type) =>
        new(SsaCilTypeKind.Exact, type);

    public static SsaCilType Join(SsaCilType left, SsaCilType right)
    {
        if (left.Kind == SsaCilTypeKind.Undefined)
            return right;
        if (right.Kind == SsaCilTypeKind.Undefined)
            return left;
        if (left.Kind == SsaCilTypeKind.Conflict || right.Kind == SsaCilTypeKind.Conflict)
            return Conflict;
        if (left.Kind == SsaCilTypeKind.Null && right.Kind == SsaCilTypeKind.Null)
            return Null;
        if (left.Kind == SsaCilTypeKind.Null && IsReference(right.Type))
            return right;
        if (right.Kind == SsaCilTypeKind.Null && IsReference(left.Type))
            return left;
        if (left.Kind != SsaCilTypeKind.Exact || right.Kind != SsaCilTypeKind.Exact)
            return Conflict;
        return Same(left.Type!, right.Type!) ? left : Conflict;
    }

    private static bool Same(TypeSignature left, TypeSignature right) =>
        left.FullName == right.FullName && SafeIsValueType(left) == SafeIsValueType(right);

    private static bool IsReference(TypeSignature? type) =>
        type is not null && !SafeIsValueType(type)
        && type is not ByReferenceTypeSignature
        && type is not PointerTypeSignature
        && type is not FunctionPointerTypeSignature;

    private static bool SafeIsValueType(TypeSignature type)
    {
        try { return type.IsValueType; }
        catch { return false; }
    }

    public override string ToString() => Kind == SsaCilTypeKind.Exact
        ? Type?.FullName ?? "<missing>" : Kind.ToString();
}

internal sealed class SsaCilTypeResult
{
    public SsaCilTypeResult(
        SsaGraph graph,
        IReadOnlyDictionary<int, SsaCilType> values,
        bool converged,
        int iterations)
    {
        Graph = graph;
        Values = values;
        Converged = converged;
        Iterations = iterations;
    }

    public SsaGraph Graph { get; }
    public IReadOnlyDictionary<int, SsaCilType> Values { get; }
    public bool Converged { get; }
    public int Iterations { get; }
}
