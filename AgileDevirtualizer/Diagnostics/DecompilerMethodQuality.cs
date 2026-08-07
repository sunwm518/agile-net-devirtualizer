using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.Loader;
using System.Text.RegularExpressions;

namespace AgileDevirtualizer.Diagnostics;

internal sealed record DecompilerMethodQuality(
    bool Available,
    int Lines,
    int ObjectLocals,
    int Casts,
    int Aliases,
    int TemporaryLocals,
    int Gotos,
    int Switches,
    int InfiniteLoops,
    int MaximumNesting,
    int Score,
    string Signature,
    string? Error = null);

/// <summary>Measures decompiler-visible scaffolding in one token-addressed C# method.</summary>
internal static partial class DecompilerMethodQualityMeasurer
{
    public static DecompilerMethodQuality Measure(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        string[] lines = source.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n');
        string structuralSource = string.Join('\n', lines.Select(StripQuotedText));
        int nonBlank = lines.Count(line => !string.IsNullOrWhiteSpace(line));
        int objectLocals = ObjectLocal().Matches(structuralSource).Count;
        int casts = Cast().Matches(structuralSource).Cast<Match>()
            .Count(match => !ControlKeywords.Contains(match.Groups[1].Value));
        int aliases = lines.Count(IsSimpleAlias);
        int temporaryLocals = TemporaryLocal().Matches(structuralSource).Count;
        int gotos = WordGoto().Matches(structuralSource).Count;
        int switches = WordSwitch().Matches(structuralSource).Count;
        int infiniteLoops = InfiniteLoop().Matches(structuralSource).Count;
        int nesting = MaximumNesting(lines);
        string signature = lines.Select(line => line.Trim())
            .FirstOrDefault(line => line.Contains('(')
                && !line.StartsWith("[", StringComparison.Ordinal)
                && !line.StartsWith("//", StringComparison.Ordinal)) ?? "<unknown>";
        int score = checked(nonBlank + objectLocals * 12 + casts * 5 + aliases * 8
            + temporaryLocals * 3 + gotos * 25 + switches * 5
            + infiniteLoops * 6 + nesting * 2);
        return new DecompilerMethodQuality(true, nonBlank, objectLocals, casts,
            aliases, temporaryLocals, gotos, switches, infiniteLoops, nesting,
            score, signature);
    }

    public static DecompilerMethodQuality Unavailable(string error) => new(false,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "<unavailable>", error);

    private static readonly HashSet<string> ControlKeywords = new(StringComparer.Ordinal)
    {
        "if", "for", "foreach", "while", "switch", "catch", "lock", "using"
    };

    private static bool IsSimpleAlias(string line)
    {
        var match = AliasLine().Match(line);
        if (!match.Success)
            return false;
        string right = match.Groups[1].Value;
        return !right.Contains("new ", StringComparison.Ordinal)
            && !right.Contains('(') && !right.Contains('[')
            && !right.Contains('+') && !right.Contains('-')
            && !right.Contains('?');
    }

    private static int MaximumNesting(IEnumerable<string> lines)
    {
        int depth = 0;
        int maximum = 0;
        foreach (string line in lines)
        {
            foreach (char character in StripQuotedText(line))
            {
                if (character == '{')
                    maximum = Math.Max(maximum, ++depth);
                else if (character == '}')
                    depth = Math.Max(0, depth - 1);
            }
        }
        return maximum;
    }

    private static string StripQuotedText(string line) =>
        QuotedText().Replace(line, string.Empty);

    [GeneratedRegex(@"\bobject\s+[@A-Za-z_\\][@A-Za-z0-9_\\]*\b")]
    private static partial Regex ObjectLocal();

    [GeneratedRegex(@"\(([@A-Za-z_\\][@A-Za-z0-9_\\.<>,\[\]? ]*)\)\s*(?:[@A-Za-z_\\]|\()")]
    private static partial Regex Cast();

    [GeneratedRegex(@"^\s*(?:[A-Za-z_\\][^=;{}]*\s+)?[@A-Za-z_\\][@A-Za-z0-9_\\]*\s*=\s*([^;]+);\s*$")]
    private static partial Regex AliasLine();

    [GeneratedRegex(@"\b(?:obj|flag|num|array|enumerator|enumerable|disposable|textBox)\d*\b(?=\s*=)")]
    private static partial Regex TemporaryLocal();

    [GeneratedRegex(@"\bgoto\b")]
    private static partial Regex WordGoto();

    [GeneratedRegex(@"\bswitch\s*\(")]
    private static partial Regex WordSwitch();

    [GeneratedRegex(@"\bwhile\s*\(\s*true\s*\)|\bfor\s*\(\s*;\s*;\s*\)")]
    private static partial Regex InfiniteLoop();

    [GeneratedRegex("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'")]
    private static partial Regex QuotedText();
}

/// <summary>Hosts the installed ILSpy engine and decompiles exactly one MethodDef token at a time.</summary>
internal sealed class IlSpyMethodSourceProvider : IDisposable
{
    private readonly string _directory;
    private readonly object _decompiler;
    private readonly MethodInfo _decompile;
    private readonly Func<AssemblyLoadContext, AssemblyName, Assembly?> _resolver;

    public IlSpyMethodSourceProvider(string assemblyPath, string ilSpyDirectory,
        string? referenceDirectory = null)
    {
        _directory = Path.GetFullPath(ilSpyDirectory);
        string enginePath = Path.Combine(_directory, "ICSharpCode.Decompiler.dll");
        if (!File.Exists(enginePath))
            throw new FileNotFoundException("ICSharpCode.Decompiler.dll was not found", enginePath);

        _resolver = Resolve;
        AssemblyLoadContext.Default.Resolving += _resolver;
        var engine = AssemblyLoadContext.Default.LoadFromAssemblyPath(enginePath);
        var settingsType = engine.GetType("ICSharpCode.Decompiler.DecompilerSettings", true)!;
        var decompilerType = engine.GetType(
            "ICSharpCode.Decompiler.CSharp.CSharpDecompiler", true)!;
        object settings = Activator.CreateInstance(settingsType)!;
        SetBoolean(settingsType, settings, "RemoveDeadCode", false);
        SetBoolean(settingsType, settings, "RemoveDeadStores", false);
        var resolverType = engine.GetType(
            "ICSharpCode.Decompiler.Metadata.UniversalAssemblyResolver", true)!;
        var resolver = Activator.CreateInstance(resolverType, Path.GetFullPath(assemblyPath),
            false, null, null, PEStreamOptions.Default, MetadataReaderOptions.Default)
            ?? throw new InvalidOperationException("could not create ILSpy assembly resolver");
        if (!string.IsNullOrWhiteSpace(referenceDirectory))
            resolverType.GetMethod("AddSearchDirectory", [typeof(string)])!
                .Invoke(resolver, [Path.GetFullPath(referenceDirectory)]);
        var resolverInterface = engine.GetType(
            "ICSharpCode.Decompiler.Metadata.IAssemblyResolver", true)!;
        var constructor = decompilerType.GetConstructor(
            [typeof(string), resolverInterface, settingsType])
            ?? throw new MissingMethodException(decompilerType.FullName,
                ".ctor(string, IAssemblyResolver, DecompilerSettings)");
        _decompiler = constructor.Invoke(
            [Path.GetFullPath(assemblyPath), resolver, settings]);
        _decompile = decompilerType.GetMethod("DecompileAsString", [typeof(EntityHandle[])])
            ?? throw new MissingMethodException(decompilerType.FullName,
                "DecompileAsString(EntityHandle[])");
    }

    public string Decompile(uint token)
    {
        if ((token >> 24) != 0x06)
            throw new ArgumentOutOfRangeException(nameof(token), "token is not a MethodDef");
        EntityHandle handle = MetadataTokens.EntityHandle(unchecked((int)token));
        try
        {
            return (string)(_decompile.Invoke(_decompiler, [new[] { handle }])
                ?? throw new InvalidOperationException("ILSpy returned no source"));
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            throw exception.InnerException;
        }
    }

    public void Dispose() => AssemblyLoadContext.Default.Resolving -= _resolver;

    private Assembly? Resolve(AssemblyLoadContext context, AssemblyName name)
    {
        string candidate = Path.Combine(_directory, name.Name + ".dll");
        return File.Exists(candidate) ? context.LoadFromAssemblyPath(candidate) : null;
    }

    private static void SetBoolean(Type type, object instance, string property, bool value)
    {
        var descriptor = type.GetProperty(property, BindingFlags.Public | BindingFlags.Instance);
        if (descriptor?.CanWrite == true && descriptor.PropertyType == typeof(bool))
            descriptor.SetValue(instance, value);
    }
}
