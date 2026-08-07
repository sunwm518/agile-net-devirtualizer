using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Evaluates BCL reflection facts used by VM-runtime metadata classifiers. These calls inspect a
/// concrete Type value that the symbolic interpreter already knows, so replaying them in the target
/// would only preserve VM bookkeeping and an otherwise unnecessary runtime dependency.
/// </summary>
internal sealed partial class ExecuteInterpreter
{
    private bool TryEvaluateRuntimeMetadataCall(string @namespace, string declaringType, string name,
                                                IReadOnlyList<SymValue> args, out SymValue result)
    {
        result = new SymValue.Unknown("runtime-metadata-call");

        if (@namespace == "System" && declaringType == "Type" && name == "get_IsValueType"
            && args.Count == 1 && TryKnownTypeValue(args[0], out var inspectedType))
        {
            result = new SymValue.Operand(inspectedType.IsValueType);
            return true;
        }

        if (@namespace == "System" && declaringType == "Nullable" && name == "GetUnderlyingType"
            && args.Count == 1 && TryKnownTypeValue(args[0], out inspectedType))
        {
            result = new SymValue.Operand(inspectedType is GenericInstanceTypeSignature generic
                && generic.GenericType.IsTypeOf("System", "Nullable`1")
                && generic.TypeArguments.Count == 1
                    ? generic.TypeArguments[0]
                    : null);
            return true;
        }

        return false;
    }

    private bool TryKnownTypeValue(SymValue value, out TypeSignature type)
    {
        switch (value)
        {
            case SymValue.Operand { Value: TypeSignature signature }:
                type = signature;
                return true;
            case SymValue.Operand { Value: ITypeDefOrRef typeDefOrRef }:
                type = TypeSignatureOf(typeDefOrRef)!;
                return type is not null;
            case SymValue.Resolved { Kind: HelperRole.ResolveType, Member: ITypeDefOrRef resolvedType }:
                type = TypeSignatureOf(resolvedType)!;
                return type is not null;
            default:
                type = null!;
                return false;
        }
    }
}
