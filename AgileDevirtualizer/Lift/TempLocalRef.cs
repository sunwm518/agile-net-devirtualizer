namespace AgileDevirtualizer.Lift;

/// <summary>
/// A <see cref="LiftedOp"/> operand referencing a scratch CIL local allocated via
/// <c>ExecuteInterpreter.AllocTemp</c> — distinct from a VM local index (a plain <c>int</c>
/// operand) so <c>CilBuilder.Lower</c> can route it to the extra locals appended after the VM's
/// own declared locals.
/// </summary>
internal sealed record TempLocalRef(int Index);
