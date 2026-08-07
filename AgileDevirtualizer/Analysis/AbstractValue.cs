namespace AgileDevirtualizer.Analysis;

internal enum AbstractValueKind
{
    Unknown,
    Int32,
    Int64,
    NativeInt,
    Float32,
    Float64,
    Reference,
    ManagedPointer,
    ValueType,
}

internal enum AbstractNullability
{
    NotApplicable,
    Null,
    NonNull,
    MaybeNull,
}

/// <summary>
/// One element of the finite value lattice. Constants are retained only while every incoming path
/// agrees; the first disagreement widens to the corresponding non-constant kind.
/// </summary>
internal sealed record AbstractValue(
    AbstractValueKind Kind,
    string? ExactType,
    AbstractNullability Nullability,
    bool HasConstant,
    object? Constant)
{
    public static AbstractValue Unknown { get; } =
        new(AbstractValueKind.Unknown, null, AbstractNullability.NotApplicable, false, null);
    public static AbstractValue Int32 { get; } =
        new(AbstractValueKind.Int32, "System.Int32", AbstractNullability.NotApplicable, false, null);
    public static AbstractValue Int64 { get; } =
        new(AbstractValueKind.Int64, "System.Int64", AbstractNullability.NotApplicable, false, null);
    public static AbstractValue NativeInt { get; } =
        new(AbstractValueKind.NativeInt, "System.IntPtr", AbstractNullability.NotApplicable, false, null);
    public static AbstractValue Float32 { get; } =
        new(AbstractValueKind.Float32, "System.Single", AbstractNullability.NotApplicable, false, null);
    public static AbstractValue Float64 { get; } =
        new(AbstractValueKind.Float64, "System.Double", AbstractNullability.NotApplicable, false, null);
    public static AbstractValue Null { get; } =
        new(AbstractValueKind.Reference, null, AbstractNullability.Null, true, null);

    public static AbstractValue ConstantValue(object? value) => value switch
    {
        null => Null,
        bool or byte or sbyte or short or ushort or int or uint or char =>
            new(AbstractValueKind.Int32, "System.Int32", AbstractNullability.NotApplicable, true, value),
        long or ulong =>
            new(AbstractValueKind.Int64, "System.Int64", AbstractNullability.NotApplicable, true, value),
        float => new(AbstractValueKind.Float32, "System.Single",
            AbstractNullability.NotApplicable, true, value),
        double => new(AbstractValueKind.Float64, "System.Double",
            AbstractNullability.NotApplicable, true, value),
        string => new(AbstractValueKind.Reference, "System.String",
            AbstractNullability.NonNull, true, value),
        _ => Unknown,
    };

    public static AbstractValue Reference(string? exactType, bool nonNull = false) =>
        new(AbstractValueKind.Reference, exactType,
            nonNull ? AbstractNullability.NonNull : AbstractNullability.MaybeNull, false, null);

    public static AbstractValue ManagedPointer(string? pointedType) =>
        new(AbstractValueKind.ManagedPointer, pointedType,
            AbstractNullability.NotApplicable, false, null);

    public static AbstractValue ValueType(string? exactType) =>
        new(AbstractValueKind.ValueType, exactType,
            AbstractNullability.NotApplicable, false, null);

    public static AbstractValue Join(AbstractValue left, AbstractValue right)
    {
        if (left == right)
            return left;
        if (left.Kind == AbstractValueKind.Unknown || right.Kind == AbstractValueKind.Unknown)
            return Unknown;
        if (left.Kind != right.Kind)
            return JoinNullAndReference(left, right) ?? Unknown;

        string? exactType = string.Equals(left.ExactType, right.ExactType, StringComparison.Ordinal)
            ? left.ExactType
            : left.Kind == AbstractValueKind.Reference ? "System.Object" : null;
        var nullability = JoinNullability(left.Nullability, right.Nullability);
        bool sameConstant = left.HasConstant && right.HasConstant
            && Equals(left.Constant, right.Constant);
        return new AbstractValue(left.Kind, exactType, nullability,
            sameConstant, sameConstant ? left.Constant : null);
    }

    private static AbstractValue? JoinNullAndReference(AbstractValue left, AbstractValue right)
    {
        if (left.Kind != AbstractValueKind.Reference || right.Kind != AbstractValueKind.Reference)
            return null;
        return Reference("System.Object");
    }

    private static AbstractNullability JoinNullability(
        AbstractNullability left,
        AbstractNullability right)
    {
        if (left == right)
            return left;
        if (left == AbstractNullability.NotApplicable || right == AbstractNullability.NotApplicable)
            return AbstractNullability.NotApplicable;
        return AbstractNullability.MaybeNull;
    }

    public override string ToString()
    {
        string type = ExactType is null ? Kind.ToString() : ExactType;
        string constant = HasConstant ? $"={Constant ?? "null"}" : "";
        string nullable = Nullability == AbstractNullability.NotApplicable ? "" : $"/{Nullability}";
        return type + nullable + constant;
    }
}
