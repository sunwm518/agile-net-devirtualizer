namespace AgileDevirtualizer.Lift;

/// <summary>
/// A sentinel <see cref="LiftedOp"/> operand meaning "call <c>System.Type.GetTypeFromHandle</c>
/// here". Emitted after an <c>ldtoken</c> whenever a symbolic <c>TypeSignature</c> needs to become a
/// genuine runtime <see cref="System.Type"/> value (e.g. a resolved method's declared return type,
/// passed as a real argument to a runtime helper) — the standard CIL idiom for materialising
/// <c>typeof(X)</c>. AsmResolver's own <c>ModuleDefinition</c>/<c>ReferenceImporter</c> is only
/// available once the final method body is being built (see <c>CilBuilder</c>), so the actual method
/// import happens there; this marker just carries the intent through the lifted-op list.
/// </summary>
internal sealed class GetTypeFromHandleMarker
{
    public static readonly GetTypeFromHandleMarker Instance = new();
    private GetTypeFromHandleMarker() { }
}
