using System.Text;
using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;

namespace AgileDevirtualizer.Diagnostics;

/// <summary>
/// Opt-in, non-semantic diagnostics for the legacy lifting pipeline. Enable by setting
/// DEVIRT_DIAGNOSTICS_DIR; normal devirtualization remains allocation- and file-write-free.
/// </summary>
internal sealed class LiftDiagnosticSession
{
    private readonly string _directory;
    private readonly string _methodHeader;
    private readonly MethodDefinition _target;

    private LiftDiagnosticSession(string directory, MethodDefinition target)
    {
        _directory = directory;
        _target = target;
        _methodHeader = $"0x{target.MetadataToken.ToInt32():X8} {target.FullName}";
    }

    public static LiftDiagnosticSession? TryCreate(MethodDefinition target, DecodedMethod decoded)
    {
        string? root = Environment.GetEnvironmentVariable("DEVIRT_DIAGNOSTICS_DIR");
        if (string.IsNullOrWhiteSpace(root))
            return null;

        try
        {
            string safeName = Sanitize(target.Name?.ToString() ?? "method");
            string directory = Path.Combine(Path.GetFullPath(root),
                $"{target.MetadataToken.ToInt32():X8}-{safeName}");
            Directory.CreateDirectory(directory);
            var session = new LiftDiagnosticSession(directory, target);
            session.WriteDecoded(decoded);
            return session;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[diagnostics] could not initialize for {target}: {ex.Message}");
            return null;
        }
    }

    public void WriteLifted(DecodedMethod decoded, IReadOnlyList<List<LiftedOp>> lifted,
                            string? gap, IReadOnlyList<string> stateSnapshots,
                            IReadOnlyList<LegacyStateSnapshot> legacySnapshots)
    {
        var text = new StringBuilder().AppendLine(_methodHeader);
        for (int i = 0; i < decoded.Instructions.Count; i++)
        {
            text.AppendLine().AppendLine($"VM #{i:D4}: {decoded.Instructions[i]}");
            if (i >= lifted.Count)
            {
                text.AppendLine("  <not lifted>");
                continue;
            }
            if (lifted[i].Count == 0)
                text.AppendLine("  <no emitted operations>");
            else
                foreach (var operation in lifted[i])
                    text.AppendLine("  " + operation);
        }
        if (gap is not null)
            text.AppendLine().AppendLine("GAP: " + gap);
        Write("02-lifted-ops.txt", text.ToString());
        Write("05-stack-states.txt", _methodHeader + Environment.NewLine
            + string.Join(Environment.NewLine, stateSnapshots));
        FormalCfgDiagnostics.Write(_target, decoded, lifted, Write, legacySnapshots);
    }

    public void WriteEmitted(CilMethodBody body)
    {
        body.Instructions.CalculateOffsets();
        var text = new StringBuilder().AppendLine(_methodHeader);
        foreach (var instruction in body.Instructions)
            text.AppendLine($"IL_{instruction.Offset:X4}: {instruction}");

        text.AppendLine().AppendLine("Exception handlers:");
        for (int i = 0; i < body.ExceptionHandlers.Count; i++)
        {
            var handler = body.ExceptionHandlers[i];
            text.AppendLine($"EH#{i}: {handler.HandlerType} "
                + $"try=IL_{handler.TryStart?.Offset:X4}..IL_{handler.TryEnd?.Offset:X4} "
                + $"handler=IL_{handler.HandlerStart?.Offset:X4}..IL_{handler.HandlerEnd?.Offset:X4} "
                + $"catch={handler.ExceptionType}");
        }
        Write("07-emitted-il.txt", text.ToString());
    }

    public void WriteStatus(string status) =>
        Write("08-status.txt", _methodHeader + Environment.NewLine + status + Environment.NewLine);

    private void WriteDecoded(DecodedMethod decoded)
    {
        var instructions = new StringBuilder().AppendLine(_methodHeader)
            .AppendLine($"VM instructions: {decoded.Instructions.Count}")
            .AppendLine($"VM locals: {decoded.Locals.Count}");
        foreach (var instruction in decoded.Instructions)
            instructions.AppendLine(instruction.ToString());
        Write("01-vm-instructions.txt", instructions.ToString());

        var regions = new StringBuilder().AppendLine(_methodHeader);
        if (decoded.ExceptionHandlers.Count == 0)
            regions.AppendLine("<no exception regions>");
        for (int i = 0; i < decoded.ExceptionHandlers.Count; i++)
        {
            var handler = decoded.ExceptionHandlers[i];
            regions.AppendLine($"EH#{i}: {ClauseName(handler.ClauseType)} "
                + $"try=[{handler.TryStart}..{handler.TryEnd}] "
                + $"handler=[{handler.HandlerStart}..{handler.HandlerEnd}] "
                + $"extra={(handler.HasExtraToken ? $"0x{handler.ExtraToken:X8}" : "none")}");
        }
        Write("06-eh-regions.txt", regions.ToString());
    }

    private void Write(string fileName, string contents)
    {
        try
        {
            File.WriteAllText(Path.Combine(_directory, fileName), contents,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[diagnostics] could not write {fileName}: {ex.Message}");
        }
    }

    private static string ClauseName(int clauseType) => clauseType switch
    {
        0 => "catch",
        1 => "filter",
        2 => "finally",
        4 => "fault",
        _ => $"unknown({clauseType})",
    };

    internal static string Sanitize(string value)
    {
        // Obfuscated metadata names may consist of invisible Unicode whitespace or end in a space
        // that Windows silently strips from a directory component. Diagnostic paths only need to
        // be stable and readable; the metadata token already guarantees uniqueness.
        string safe = new(value.Select(c =>
            char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' ? c : '_').ToArray());
        safe = safe.TrimEnd('.', ' ');
        return string.IsNullOrEmpty(safe) ? "method" : safe;
    }
}
