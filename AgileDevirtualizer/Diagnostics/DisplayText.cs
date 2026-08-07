using System.Globalization;
using System.Text;

namespace AgileDevirtualizer.Diagnostics;

/// <summary>Makes obfuscated identifiers safe to print without letting control characters split logs.</summary>
internal static class DisplayText
{
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return value ?? string.Empty;

        var result = new StringBuilder(value.Length);
        foreach (char character in value)
        {
            UnicodeCategory category = char.GetUnicodeCategory(character);
            bool unsafeCharacter = char.IsControl(character)
                                   || category == UnicodeCategory.Format
                                   || (char.IsWhiteSpace(character) && character != ' ');
            if (unsafeCharacter)
                result.Append("\\u").Append(((int)character).ToString("X4", CultureInfo.InvariantCulture));
            else
                result.Append(character);
        }
        return result.ToString();
    }
}
