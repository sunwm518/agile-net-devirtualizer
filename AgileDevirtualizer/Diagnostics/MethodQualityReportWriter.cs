using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using AgileDevirtualizer.Analysis;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Diagnostics;

internal sealed record MethodQualityRow(
    string Token,
    string Method,
    string Outcome,
    string Features,
    string Layout,
    bool Optimized,
    int ExceptionHandlers,
    CilStructuralQuality Cil,
    DecompilerMethodQuality CSharp,
    string PrimaryDebt,
    int RankScore,
    IReadOnlyList<OptimizationAttempt> Attempts);

internal sealed record MethodQualitySummary(
    int Methods,
    int Decompiled,
    IReadOnlyDictionary<string, int> PrimaryDebt,
    IReadOnlyDictionary<string, int> PrimaryDebtScore,
    IReadOnlyDictionary<string, int> RejectedStages,
    IReadOnlyDictionary<string, int> Requirements);

internal sealed record MethodQualityReport(
    string Assembly,
    string Sha256,
    DateTimeOffset GeneratedUtc,
    MethodQualitySummary Summary,
    IReadOnlyList<MethodQualityRow> Methods);

/// <summary>Writes deterministic JSON and Markdown debt reports for all CFG-emission decisions.</summary>
internal static partial class MethodQualityReportWriter
{
    public static MethodQualityReport Write(ModuleDefinition module, string assemblyPath,
        CfgEmissionSummary emission, string ilSpyDirectory, string jsonPath,
        string? referenceDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(module);
        string fullAssembly = Path.GetFullPath(assemblyPath);
        var rows = new List<MethodQualityRow>();
        using var decompiler = new IlSpyMethodSourceProvider(fullAssembly, ilSpyDirectory,
            referenceDirectory);

        foreach (var item in emission.MethodDecisions.OrderBy(item => item.Token))
        {
            var token = new MetadataToken(item.Token);
            if (!module.TryLookupMember(token, out var member)
                || member is not MethodDefinition method
                || method.CilMethodBody is not { } body)
                continue;

            DecompilerMethodQuality csharp;
            try
            {
                string source = decompiler.Decompile(item.Token);
                csharp = string.IsNullOrWhiteSpace(source)
                    ? DecompilerMethodQualityMeasurer.Unavailable(
                        "ILSpy folds this MethodDef into another member")
                    : DecompilerMethodQualityMeasurer.Measure(source);
            }
            catch (Exception exception)
            {
                csharp = DecompilerMethodQualityMeasurer.Unavailable(
                    $"{exception.GetType().Name}: {exception.Message}");
            }

            var decision = item.Decision;
            var attempts = decision.Attempts ?? [];
            var cil = CilStructuralQualityGate.Measure(body);
            string layout = ExtractLayout(decision);
            string debt = ClassifyPrimaryDebt(decision.Features, attempts, csharp, cil,
                layout);
            int score = csharp.Available
                ? checked(csharp.Score * 10 + cil.Locals * 2 + cil.Aliases * 3
                    + body.ExceptionHandlers.Count * 5)
                : cil.Cost;
            rows.Add(new MethodQualityRow($"0x{item.Token:X8}", item.Identity,
                decision.Outcome.ToString(), decision.Features.ToString(),
                layout, decision.Optimized,
                body.ExceptionHandlers.Count, cil, csharp, debt, score, attempts));
        }

        var ordered = rows.OrderByDescending(row => row.RankScore)
            .ThenBy(row => row.Token, StringComparer.Ordinal).ToArray();
        var summary = new MethodQualitySummary(ordered.Length,
            ordered.Count(row => row.CSharp.Available),
            Count(ordered.Select(row => row.PrimaryDebt)),
            Sum(ordered, row => row.PrimaryDebt, row => row.RankScore),
            Count(ordered.SelectMany(row => row.Attempts
                .Where(attempt => attempt.Outcome == "rejected")
                .Select(attempt => attempt.Stage))),
            Count(ordered.SelectMany(row => EnumerateRequirements(row.Attempts))));
        var report = new MethodQualityReport(Path.GetFileName(fullAssembly),
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fullAssembly))),
            DateTimeOffset.UtcNow, summary, ordered);

        string fullJson = Path.GetFullPath(jsonPath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullJson)!);
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            Converters = { new JsonStringEnumConverter() }
        };
        File.WriteAllText(fullJson, JsonSerializer.Serialize(report, options),
            new UTF8Encoding(false));
        File.WriteAllText(Path.ChangeExtension(fullJson, ".md"), ToMarkdown(report),
            new UTF8Encoding(false));
        return report;
    }

    private static string ExtractLayout(CfgEmissionDecision decision)
    {
        var match = Layout().Match(decision.Reason);
        if (match.Success)
            return match.Groups[1].Value.Trim();
        return decision.Attempts?.Any(attempt => attempt.Stage == "eh-ssa"
            && attempt.Outcome == "selected") == true ? "eh-ssa" : "semantic";
    }

    private static string ClassifyPrimaryDebt(CfgControlFlowFeatures features,
        IReadOnlyList<OptimizationAttempt> attempts, DecompilerMethodQuality csharp,
        CilStructuralQuality cil, string layout)
    {
        if (features.HasFlag(CfgControlFlowFeatures.ExceptionRegions))
        {
            var local = attempts.FirstOrDefault(attempt =>
                attempt.Stage == "eh-local-coalescing");
            if (local?.Outcome == "rejected")
                return "EH local/data-flow cleanup";
            var expression = attempts.FirstOrDefault(attempt =>
                attempt.Stage == "eh-expression-scheduling");
            if (expression?.Outcome == "rejected")
                return "EH expression scheduling";
        }

        var requirements = attempts.Aggregate(SsaLoweringFeature.None,
            (value, attempt) => value | attempt.Requirements);
        if (requirements.HasFlag(SsaLoweringFeature.ManagedPointer))
            return "Managed-pointer lowering";
        if (requirements.HasFlag(SsaLoweringFeature.AddressOperation))
            return "Address-operation lowering";
        if (requirements.HasFlag(SsaLoweringFeature.Prefix))
            return "Prefix-aware lowering";
        if (requirements.HasFlag(SsaLoweringFeature.UnknownValueType))
            return "Exact type/materialization";

        var rejection = attempts.FirstOrDefault(attempt => attempt.Outcome == "rejected"
            && (attempt.Reason.Contains("exact CIL type", StringComparison.OrdinalIgnoreCase)
                || attempt.Reason.Contains("type conflict", StringComparison.OrdinalIgnoreCase)));
        if (rejection is not null)
            return "Exact type/materialization";
        if (layout is "semantic" or "lossless" or "pruned"
            && attempts.Any(attempt => attempt.Outcome == "rejected"
            && (attempt.Reason.Contains("structural cost", StringComparison.OrdinalIgnoreCase)
                || attempt.Reason.Contains("instruction growth", StringComparison.OrdinalIgnoreCase))))
            return "Structural quality gate";
        if (csharp.Available && (csharp.ObjectLocals > 0 || csharp.Aliases > 1
            || csharp.Casts > 4 || csharp.TemporaryLocals > 5))
            return "Residual alias/cast canonicalization";
        if (cil.BasicBlocks > 10 || csharp.InfiniteLoops > 0)
            return "Control-flow canonicalization";
        return "Low residual debt";
    }

    private static IReadOnlyDictionary<string, int> Count(IEnumerable<string> values) =>
        values.GroupBy(value => value, StringComparer.Ordinal)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(),
                StringComparer.Ordinal);

    private static IReadOnlyDictionary<string, int> Sum(IEnumerable<MethodQualityRow> rows,
        Func<MethodQualityRow, string> key, Func<MethodQualityRow, int> value) =>
        rows.GroupBy(key, StringComparer.Ordinal)
            .OrderByDescending(group => group.Sum(value))
            .ThenBy(group => group.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Sum(value),
                StringComparer.Ordinal);

    private static IEnumerable<string> EnumerateRequirements(
        IReadOnlyList<OptimizationAttempt> attempts)
    {
        var combined = attempts.Aggregate(SsaLoweringFeature.None,
            (value, attempt) => value | attempt.Requirements);
        foreach (var feature in Enum.GetValues<SsaLoweringFeature>())
            if (feature != SsaLoweringFeature.None && combined.HasFlag(feature))
                yield return feature.ToString();
    }

    private static string ToMarkdown(MethodQualityReport report)
    {
        var text = new StringBuilder();
        text.AppendLine("# Per-method decompilation quality audit").AppendLine();
        text.AppendLine($"- Assembly: `{Escape(report.Assembly)}`");
        text.AppendLine($"- SHA-256: `{report.Sha256}`");
        text.AppendLine($"- Methods: {report.Summary.Methods}");
        text.AppendLine($"- Token-addressed ILSpy results: {report.Summary.Decompiled}");
        text.AppendLine("- This report is observational; it never changes emission selection.")
            .AppendLine();
        AppendCounts(text, "Primary debt", report.Summary.PrimaryDebt);
        AppendCounts(text, "Primary debt weighted score", report.Summary.PrimaryDebtScore);
        AppendCounts(text, "Rejected optimization stages", report.Summary.RejectedStages);
        AppendCounts(text, "Observed SSA requirements", report.Summary.Requirements);
        text.AppendLine("## Ranked methods").AppendLine();
        text.AppendLine("| Rank | Token | Layout | C# lines | CIL locals | CIL casts | C# objects | C# casts | Aliases | Blocks | EH | Primary debt |");
        text.AppendLine("|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|");
        int rank = 0;
        foreach (var row in report.Methods)
        {
            text.Append('|').Append(++rank).Append('|').Append(row.Token).Append('|')
                .Append(Escape(row.Layout)).Append('|').Append(row.CSharp.Lines).Append('|')
                .Append(row.Cil.Locals).Append('|').Append(row.Cil.Casts).Append('|')
                .Append(row.CSharp.ObjectLocals).Append('|').Append(row.CSharp.Casts).Append('|')
                .Append(row.Cil.Aliases).Append('|').Append(row.Cil.BasicBlocks).Append('|')
                .Append(row.ExceptionHandlers).Append('|').Append(Escape(row.PrimaryDebt))
                .AppendLine("|");
        }
        return text.ToString();
    }

    private static void AppendCounts(StringBuilder text, string heading,
        IReadOnlyDictionary<string, int> counts)
    {
        text.Append("## ").AppendLine(heading).AppendLine();
        foreach (var (name, count) in counts)
            text.Append("- ").Append(Escape(name)).Append(": ").AppendLine(count.ToString());
        text.AppendLine();
    }

    private static string Escape(string value) => value.Replace("|", "\\|",
        StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal)
        .Replace("\n", " ", StringComparison.Ordinal);

    [GeneratedRegex(@"(?:^|;)\s*layout=([^;]+)")]
    private static partial Regex Layout();
}
