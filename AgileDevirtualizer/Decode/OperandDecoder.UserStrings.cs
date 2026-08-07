using AsmResolver.DotNet;

namespace AgileDevirtualizer.Decode;

internal static partial class OperandDecoder
{
    /// <summary>
    /// Reserves a native <c>ldstr</c> entry using the same projected #US layout as VM operand
    /// decoding. Returning false means the string must be materialised without an ldstr token.
    /// </summary>
    internal static bool TryReserveUserString(ModuleDefinition module, string value)
    {
        var index = UserStringsByModule.GetValue(module, BuildUserStringIndex);
        uint rawToken = index.RawTokenFor(value);
        return (rawToken & 0xFF000000u) == 0x70000000u;
    }
}
