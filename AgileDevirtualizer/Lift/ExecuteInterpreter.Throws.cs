using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Distinguishes an original program throw from a VM guard throw. A semantic throw consumes a
    /// live value popped from the VM stack whose tracked CLR type derives from System.Exception;
    /// runtime guards construct an unmodelled VM exception and therefore remain rejected.
    /// </summary>
    private void EmitSemanticThrowOrReject()
    {
        var exception = Pop();
        if (TryEmitRethrow(exception))
            return;

        if (exception is SymValue.OnStack
            {
                KnownType: { } knownType,
                Peeked: false,
                ManagedPointer: false,
            }
            && IsExceptionType(knownType))
        {
            Emit(CilOpCodes.Throw);
            _termKind = TermKind.Resolved;
            return;
        }

        throw new LiftUnsupported("execute path reached a throw (unmodelled predicate)");
    }

    private bool IsExceptionType(TypeSignature type)
    {
        var current = ResolveTypeDef(type);
        var visited = new HashSet<TypeDefinition>();
        while (current is not null && visited.Add(current))
        {
            if (current.IsTypeOf("System", "Exception"))
                return true;
            current = ResolveTypeDef(current.BaseType);
        }
        return false;
    }
}
