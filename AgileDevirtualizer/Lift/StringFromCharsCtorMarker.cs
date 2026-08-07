namespace AgileDevirtualizer.Lift;

/// <summary>
/// Sentinel operand for constructing System.String from the char[] currently on the CIL stack.
/// CilBuilder creates the actual member reference against the protected target's own corlib.
/// </summary>
internal sealed class StringFromCharsCtorMarker
{
    public static readonly StringFromCharsCtorMarker Instance = new();
    private StringFromCharsCtorMarker() { }
}
