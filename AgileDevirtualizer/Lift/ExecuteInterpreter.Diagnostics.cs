namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Captures only the stable, method-level state already maintained by the legacy lifter. This
    /// method is called exclusively by opt-in diagnostics and does not influence lifting.
    /// </summary>
    internal LegacyStateSnapshot CaptureLegacyState(int vmInstructionIndex)
    {
        var stack = _vmValueTypes
            .Reverse()
            .Select(value => new LegacyStackValueSnapshot(
                value.Type?.FullName,
                value.Type?.IsValueType ?? false,
                value.ManagedPointer,
                value.KnownNull))
            .ToArray();
        var locals = _vmLocalKnownTypes.ToDictionary(
            pair => pair.Key,
            pair => new LegacyLocalValueSnapshot(
                pair.Value?.FullName,
                pair.Value?.IsValueType ?? false));
        return new LegacyStateSnapshot(vmInstructionIndex, stack, locals);
    }
}
