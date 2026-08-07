using System.Globalization;

namespace AgileDevirtualizer.Cli;

/// <summary>
/// Parses an optional, repeatable list of metadata tokens that must remain VM-backed. This is a
/// diagnostic safety valve for runtime bisection; it never changes the default acceptance policy.
/// </summary>
internal static class TokenExclusions
{
    public static HashSet<uint> Parse(string[] args)
    {
        var result = new HashSet<uint>();
        for (int i = 0; i < args.Length; i++)
        {
            if (!string.Equals(args[i], "--exclude", StringComparison.OrdinalIgnoreCase))
                continue;
            if (++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException("--exclude requires one or more comma-separated method tokens");

            foreach (string item in args[i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string tokenText = item.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? item[2..] : item;
                if (!uint.TryParse(tokenText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint token)
                    || (token >> 24) != 0x06 || (token & 0x00FFFFFF) == 0)
                    throw new ArgumentException($"invalid MethodDef token for --exclude: {item}");
                result.Add(token);
            }
        }
        return result;
    }
}
