namespace AgileDevirtualizer.Decode;

/// <summary>
/// Marks a string read from a VM instruction's operand blob. Keeping it distinct from an ordinary
/// CLR string prevents the metadata writer from reusing a same-valued, oversized #US entry that
/// cannot be encoded by native CIL ldstr.
/// </summary>
internal sealed record DecodedStringLiteral(string Value, uint RawToken);
