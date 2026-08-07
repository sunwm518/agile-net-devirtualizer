using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Models Agile's structurally recognized <c>void(ref object, Type)</c> conversion helper. The
    /// helper uses <c>Enum.ToObject</c> for enum targets; the raw integral representation already on
    /// the reconstructed CIL stack therefore needs no conversion opcode, but its tracked type must
    /// become the concrete enum so a later box/constrained call uses the original program type.
    /// </summary>
    private void DoCoerceByRef(IMethodDescriptor method)
    {
        int count = ParamCount(method) + (HasThis(method) ? 1 : 0);
        var args = new SymValue[count];
        for (int i = count - 1; i >= 0; i--)
            args[i] = Pop();

        if (args.Length == 2
            && args[0] is SymValue.HandlerLocalAddr address
            && TryKnownTypeValue(args[1], out var requestedType))
        {
            TypeSignature targetType = NullableUnderlyingType(requestedType) ?? requestedType;
            var current = _locals.GetValueOrDefault(address.Index, address.Value);
            _locals[address.Index] = WithKnownType(current, targetType);
        }

        if (!(SigReturn(method)?.IsTypeOf("System", "Void") ?? true))
            _eval.Push(new SymValue.Unknown("byref-coercion-result"));
    }

    private static TypeSignature? NullableUnderlyingType(TypeSignature type) =>
        type is GenericInstanceTypeSignature generic
        && generic.GenericType.IsTypeOf("System", "Nullable`1")
        && generic.TypeArguments.Count == 1
            ? generic.TypeArguments[0]
            : null;
}
