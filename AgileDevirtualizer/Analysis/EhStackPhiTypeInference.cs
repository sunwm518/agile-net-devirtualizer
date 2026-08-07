using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Recovers a storage type for EH evaluation-stack phis when metadata-level primitive types differ
/// but the CLI evaluation stack represents them with the same integral category. This is deliberately
/// narrower than the general SSA type lattice and is consumed only by detached EH shadow planning.
/// </summary>
internal static class EhStackPhiTypeInference
{
    public static bool TryInfer(
        ModuleDefinition module,
        SsaPhi phi,
        SccpResult sccp,
        SsaCilTypeResult types,
        out TypeSignature? type)
    {
        if (types.Values[phi.Result.Id] is { Kind: SsaCilTypeKind.Exact, Type: { } exact })
        {
            type = exact;
            return true;
        }

        var joined = SsaCilType.Undefined;
        foreach (var input in SsaPhiCongruence.ExecutableInputs(phi, sccp))
            joined = Join(module, joined, types.Values[input.ValueId]);
        if (joined is { Kind: SsaCilTypeKind.Exact, Type: { } inferred })
        {
            type = inferred;
            return true;
        }

        type = null;
        return false;
    }

    internal static SsaCilType Join(
        ModuleDefinition module,
        SsaCilType left,
        SsaCilType right) => SsaCilType.Join(
            Canonicalize(module, left), Canonicalize(module, right));

    public static bool IsCompatible(
        ModuleDefinition module,
        SsaCilType source,
        TypeSignature destination)
    {
        if (source.Kind == SsaCilTypeKind.Null)
            return IsReference(destination);
        var canonicalSource = Canonicalize(module, source);
        var canonicalDestination = Canonicalize(module, SsaCilType.Exact(destination));
        return canonicalSource is { Kind: SsaCilTypeKind.Exact, Type: { } sourceType }
            && canonicalDestination is { Kind: SsaCilTypeKind.Exact, Type: { } destinationType }
            && Same(sourceType, destinationType);
    }

    private static SsaCilType Canonicalize(ModuleDefinition module, SsaCilType value)
    {
        if (value is not { Kind: SsaCilTypeKind.Exact, Type: { } type })
            return value;
        return type.FullName switch
        {
            "System.Boolean" or "System.Byte" or "System.SByte" or "System.Char"
                or "System.Int16" or "System.UInt16" or "System.Int32"
                or "System.UInt32" => SsaCilType.Exact(module.CorLibTypeFactory.Int32),
            "System.Int64" or "System.UInt64" =>
                SsaCilType.Exact(module.CorLibTypeFactory.Int64),
            "System.IntPtr" or "System.UIntPtr" =>
                SsaCilType.Exact(module.CorLibTypeFactory.IntPtr),
            _ => value,
        };
    }

    private static bool Same(TypeSignature left, TypeSignature right) =>
        left.FullName == right.FullName
        && SafeIsValueType(left) == SafeIsValueType(right);

    private static bool IsReference(TypeSignature type) =>
        !SafeIsValueType(type)
        && type is not ByReferenceTypeSignature
        && type is not PointerTypeSignature
        && type is not FunctionPointerTypeSignature;

    private static bool SafeIsValueType(TypeSignature type)
    {
        try { return type.IsValueType; }
        catch { return false; }
    }
}
