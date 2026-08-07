using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>Materializes values carried through the VM as managed-pointer wrappers.</summary>
internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// The VM can represent an array-element read by pushing its by-ref wrapper. Assigning that
    /// wrapper to an ordinary VM local reads the pointed-to element; it does not turn the local into
    /// a CLR by-ref local. Reconstruct the missing dereference before the emitted <c>stloc</c>.
    /// </summary>
    private SymValue DereferenceManagedPointerForLocalStore(SymValue value, TypeSignature? localType)
    {
        if (value is not SymValue.OnStack { ManagedPointer: true } pointer
            || localType is ByReferenceTypeSignature)
            return value;

        if (pointer.KnownType is not { } pointedType)
            throw new LiftUnsupported("managed-pointer local store has an unknown pointed-to type");

        Emit(CilOpCodes.Ldobj, pointedType.ToTypeDefOrRef());
        return new SymValue.OnStack(pointedType);
    }
}
