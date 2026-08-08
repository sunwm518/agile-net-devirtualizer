using AgileDevirtualizer.Cli;
using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Diagnostics;
using AgileDevirtualizer.Emit;
using AgileDevirtualizer.Lift;
using AgileDevirtualizer.Resource;
using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;

// Wraps the whole run: an unhandled exception's default .NET stack trace embeds the build/run
// machine's own absolute file paths (e.g. a developer's Windows username) — never acceptable for a
// publicly-distributed CLI tool. Anything genuinely unexpected here is reported by message only;
// the full exception (with its stack trace) is still available opt-in via DBG=1, matching the
// existing per-method failure convention below.
try
{
if (args.Length < 2)
{
    Console.Error.WriteLine("usage: AgileDevirtualizer <input-assembly> <VMRuntime.dll> [output] " +
                            "[--cfg-emission | --legacy-emission] " +
                            "[--optimize | --no-optimize] [--typed-ssa] [--ssa-phi] " +
                            "[--cast-shadow | --cast-cleanup] " +
                            "[--ssa-edge-shadow] [--eh-ssa | --no-eh-ssa] " +
                            "[--eh-ssa-validation-artifact | --eh-ssa-copy-validation-artifact] " +
                            "[--quality-report path --ilspy-directory path " +
                            "--quality-reference-directory path] " +
                            "[--exclude token[,token...]] [--dump [token|index]]");
    return 1;
}

if (args.Contains("--cfg-emission") && args.Contains("--legacy-emission"))
{
    Console.Error.WriteLine("[!] --cfg-emission and --legacy-emission are mutually exclusive.");
    return 4;
}

if (args.Contains("--optimize") && args.Contains("--no-optimize"))
{
    Console.Error.WriteLine("[!] --optimize and --no-optimize are mutually exclusive.");
    return 4;
}
if (args.Contains("--legacy-emission") && args.Contains("--optimize"))
{
    Console.Error.WriteLine("[!] --optimize cannot be combined with --legacy-emission.");
    return 4;
}
if (args.Contains("--cast-cleanup") && args.Contains("--legacy-emission"))
{
    Console.Error.WriteLine("[!] --cast-cleanup requires semantic emission.");
    return 4;
}
if (args.Contains("--cast-shadow") && args.Contains("--legacy-emission"))
{
    Console.Error.WriteLine("[!] --cast-shadow requires semantic emission.");
    return 4;
}
if (args.Contains("--typed-ssa")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine("[!] --typed-ssa requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--ssa-phi")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine("[!] --ssa-phi requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--ssa-edge-shadow")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine("[!] --ssa-edge-shadow requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--eh-ssa-validation-artifact")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine(
        "[!] --eh-ssa-validation-artifact requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--eh-ssa-copy-validation-artifact")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine(
        "[!] --eh-ssa-copy-validation-artifact requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--eh-ssa-validation-artifact")
    && args.Contains("--eh-ssa-copy-validation-artifact"))
{
    Console.Error.WriteLine(
        "[!] EH SSA validation artifact modes are mutually exclusive.");
    return 4;
}
if (args.Contains("--eh-ssa")
    && (args.Contains("--legacy-emission") || args.Contains("--no-optimize")))
{
    Console.Error.WriteLine("[!] --eh-ssa requires optimized semantic emission.");
    return 4;
}
if (args.Contains("--eh-ssa") && args.Contains("--eh-ssa-validation-artifact"))
{
    Console.Error.WriteLine(
        "[!] --eh-ssa and --eh-ssa-validation-artifact are mutually exclusive.");
    return 4;
}
if (args.Contains("--eh-ssa") && args.Contains("--eh-ssa-copy-validation-artifact"))
{
    Console.Error.WriteLine(
        "[!] --eh-ssa and --eh-ssa-copy-validation-artifact are mutually exclusive.");
    return 4;
}
if (args.Contains("--eh-ssa") && args.Contains("--no-eh-ssa"))
{
    Console.Error.WriteLine("[!] --eh-ssa and --no-eh-ssa are mutually exclusive.");
    return 4;
}
if (args.Contains("--no-eh-ssa") && args.Contains("--eh-ssa-validation-artifact"))
{
    Console.Error.WriteLine(
        "[!] --no-eh-ssa and --eh-ssa-validation-artifact are mutually exclusive.");
    return 4;
}
if (args.Contains("--no-eh-ssa") && args.Contains("--eh-ssa-copy-validation-artifact"))
{
    Console.Error.WriteLine(
        "[!] --no-eh-ssa and --eh-ssa-copy-validation-artifact are mutually exclusive.");
    return 4;
}

string? qualityReportPath = args.SkipWhile(argument => argument != "--quality-report")
    .Skip(1).FirstOrDefault();
string? ilSpyDirectory = args.SkipWhile(argument => argument != "--ilspy-directory")
    .Skip(1).FirstOrDefault();
string? qualityReferenceDirectory = args
    .SkipWhile(argument => argument != "--quality-reference-directory")
    .Skip(1).FirstOrDefault();
if ((qualityReportPath is null) != (ilSpyDirectory is null))
{
    Console.Error.WriteLine(
        "[!] --quality-report and --ilspy-directory must be supplied together.");
    return 4;
}

string inputPath = args[0];
string runtimePath = args[1];
bool dump = args.Contains("--dump");
string? dumpFilter = dump ? args.SkipWhile(a => a != "--dump").Skip(1).FirstOrDefault() : null;

Console.WriteLine($"[*] Loading VM runtime: {runtimePath}");
var runtime = RuntimeModel.Load(runtimePath);
Console.WriteLine($"    handler base : {runtime.HandlerBase.FullName}");
Console.WriteLine($"    context type : {runtime.ContextType.FullName}");
Console.WriteLine($"    opcodes      : {runtime.Handlers.Count}  " +
                  $"(read {runtime.Handlers.Count(h => h.ReadMethod != null)}, " +
                  $"exec {runtime.Handlers.Count(h => h.ExecuteMethod != null)})");

if (args.Contains("--classify"))
{
    var cc = ConditionClassifier.Build(runtime);
    Console.WriteLine("[*] Comparison primitives recognized by probing (not by name):");
    foreach (var t in runtime.Module.GetAllTypes())
        foreach (var m in t.Methods)
            if (m is { IsStatic: true } && (m.Signature?.ReturnType?.IsTypeOf("System", "Boolean") ?? false)
                && cc.Relation(m) is { } rel)
                Console.WriteLine($"    {rel,-6} {t.Name}.{m.Name}");
    return 0;
}

if (args.Contains("--helpers"))
{
    var helpers = RuntimeHelpers.Build(runtime);
    var roles = new SortedDictionary<AgileDevirtualizer.Lift.HelperRole, List<string>>();
    foreach (var t in runtime.Module.GetAllTypes())
        foreach (var m in t.Methods)
        {
            var r = helpers.RoleOf(m);
            if (r != AgileDevirtualizer.Lift.HelperRole.None)
                (roles.TryGetValue(r, out var l) ? l : roles[r] = []).Add($"{t.Name}.{m.Name}");
        }
    Console.WriteLine("[*] Runtime helpers recognized by BCL anchor (not by name):");
    foreach (var (role, list) in roles)
        Console.WriteLine($"    {role,-14}: {list.Count} method(s)  e.g. {string.Join(", ", list.Take(4))}");
    return 0;
}

if (args.Contains("--vocab"))
{
    var v = RuntimeVocabulary.Build(runtime);
    Console.WriteLine("[*] VM vocabulary (identified structurally, not by name):");
    Console.WriteLine($"    value/box type : {v.ValueType.Name}");
    Console.WriteLine($"    stack type     : {v.StackType.Name}");
    Console.WriteLine($"      push         : {string.Join(", ", v.Push.Select(p => p.Name))}");
    Console.WriteLine($"      pop / peek   : {v.Pop.Name} / {v.Peek?.Name}");
    Console.WriteLine($"    ctx.getStack   : {v.GetStack.Name}");
    Console.WriteLine($"    ctx.getLocals  : {v.GetLocals.Name}");
    Console.WriteLine($"    ctx.getArgs    : {v.GetArgs.Name}");
    Console.WriteLine($"    ctx.setLocal   : {v.SetLocal?.Name}");
    Console.WriteLine($"    ctx.getIP/setIP: {v.GetIp.Name} / {v.SetIp.Name}");
    Console.WriteLine($"    ctx.setReturn  : {v.SetReturn?.Name}");
    return 0;
}

Console.WriteLine($"[*] Loading input assembly: {inputPath}");
// Give the module an assembly resolver rooted at its own folder so cross-assembly references
// (framework fields/methods) resolve â€” the lifter needs field static-ness etc. from real defs.
var readerParams = new AsmResolver.DotNet.Serialized.ModuleReaderParameters(Path.GetDirectoryName(Path.GetFullPath(inputPath)));
var module = ModuleDefinition.FromFile(inputPath, readerParams);

var found = VMResource.Find(module);
if (found is null)
{
    Console.Error.WriteLine("[!] No _CSVM virtualized-method table found â€” is this sample VM-protected?");
    return 2;
}
var (resource, methods) = found.Value;
Console.WriteLine($"[*] _CSVM resource '{resource.Name}': {methods.Count} virtualized method(s).");

// Devirtualize mode: a 3rd positional arg (not a flag) is the output path.
// The output path is a bare positional arg after the runtime DLL â€” but not one consumed as a
// filter value for --dump/--lift (e.g. `--lift 06000008` is a filter, not a write request).
var flagsWithValue = new HashSet<string>
{
    "--dump", "--lift", "--exclude", "--quality-report", "--ilspy-directory",
    "--quality-reference-directory"
};
string? outputPath = null;
for (int i = 2; i < args.Length; i++)
{
    if (args[i].StartsWith("--")) { if (flagsWithValue.Contains(args[i])) i++; continue; }
    outputPath = args[i];
    break;
}
if (outputPath is not null)
{
    HashSet<uint> excludedTokens;
    try { excludedTokens = TokenExclusions.Parse(args); }
    catch (ArgumentException ex)
    {
        Console.Error.WriteLine($"[!] {ex.Message}");
        return 4;
    }
    var vocab = RuntimeVocabulary.Build(runtime);
    var interpreter = new ExecuteInterpreter(module, vocab, RuntimeHelpers.Build(runtime), ConditionClassifier.Build(runtime));
    bool useSemanticEmission = !args.Contains("--legacy-emission");
    var result = Devirtualizer.Run(module, runtime, methods, interpreter, excludedTokens,
        useSemanticEmission, optimizeSemanticEmission: !args.Contains("--no-optimize"),
        enableTypedSsa: args.Contains("--typed-ssa"),
        enablePhiSsa: args.Contains("--ssa-phi"),
        enableEdgeSsaShadow: args.Contains("--ssa-edge-shadow"),
        enableEhSsaValidationArtifact: args.Contains("--eh-ssa-validation-artifact"),
        enableEhSsaCopyValidationArtifact:
            args.Contains("--eh-ssa-copy-validation-artifact"),
        enableEhSsa: !args.Contains("--no-eh-ssa")
            && !args.Contains("--eh-ssa-validation-artifact")
            && !args.Contains("--eh-ssa-copy-validation-artifact"),
        enableRedundantCastShadow: args.Contains("--cast-shadow"),
        enableRedundantCastCleanup: args.Contains("--cast-cleanup"));
    bool fullyDevirtualized = RuntimeDependencyCleanup.RemoveVmResourceWhenComplete(module, resource, result);
    Console.WriteLine($"[*] Devirtualized {result.Devirtualized}/{result.Total} method(s).");
    if (result.CfgEmission.Enabled)
    {
        Console.WriteLine($"[*] CFG emission: candidates={result.CfgEmission.Candidates}, " +
                          $"activated={result.CfgEmission.Activated}, " +
                          $"optimized={result.CfgEmission.Optimized}, " +
                          $"semantic-failed={result.CfgEmission.SemanticFailures}, " +
                          $"not-selected={result.CfgEmission.NotSelected}.");
        foreach (var (feature, count) in result.CfgEmission.FeatureCounts
                     .OrderBy(pair => pair.Key))
            Console.WriteLine($"    {feature,-18} {count}");
        if (args.Contains("--show-cfg-decisions"))
            foreach (string decision in result.CfgEmission.Decisions)
                Console.WriteLine("      Â· " + decision);
    }
    var byCategory = new SortedDictionary<string, int>();
    foreach (var f in result.Failures)
    {
        int c = f.IndexOf(':');
        string rest = c >= 0 ? f[(c + 1)..].Trim() : f;
        string cat = rest.StartsWith("rejected") ? rest[..Math.Min(rest.Length, rest.IndexOf(':') > 0 ? rest.IndexOf(':') : rest.Length)]
                   : rest.StartsWith("not fully lifted") ? rest.Split('(')[^1].TrimEnd(')')
                   : rest;
        byCategory[cat] = byCategory.GetValueOrDefault(cat) + 1;
    }
    foreach (var (cat, cnt) in byCategory.OrderByDescending(kv => kv.Value))
        Console.WriteLine($"    x{cnt,-3} {cat}");
    if (args.Contains("--show-failures"))
        foreach (var f in result.Failures.Take(30))
            Console.WriteLine($"      Â· {f}");
    Console.WriteLine($"[*] Writing: {outputPath}");
    if (result.Devirtualized == 0)
        Console.WriteLine("    no accepted methods; copying the original assembly byte-for-byte");
    Devirtualizer.WriteTarget(module, inputPath, outputPath, result.Devirtualized,
        preserveAllTokens: fullyDevirtualized ? false : null);
    // Every partial output still needs its VM runtime for rejected methods. A devirtualized method
    // may additionally call a transparent runtime helper whose visibility CilBuilder widened, so in
    // that case write the modified runtime; for a zero-success run copy the original byte-for-byte.
    string runtimeOutPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".", Path.GetFileName(runtimePath));
    if (result.Devirtualized == 0)
    {
        Console.WriteLine($"[*] Copying unchanged runtime: {runtimeOutPath}");
        Devirtualizer.WriteTarget(runtime.Module, runtimePath, runtimeOutPath, devirtualized: 0);
    }
    else if (RuntimeDependencyCleanup.OutputReferencesRuntime(outputPath, runtime))
    {
        if (string.Equals(Path.GetFullPath(runtimeOutPath), Path.GetFullPath(runtimePath),
                StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("[!] Refusing to overwrite the input VM runtime. " +
                                    "Write the devirtualized assembly to a separate staging directory.");
            return 5;
        }
        Console.WriteLine($"[*] Writing runtime (visibility-widened where referenced): {runtimeOutPath}");
        Devirtualizer.Write(runtime.Module, runtimeOutPath);
    }
    else
    {
        Console.WriteLine("[*] Standalone output: no VM runtime reference remains.");
    }
    if (qualityReportPath is not null && ilSpyDirectory is not null)
    {
        var qualityReport = MethodQualityReportWriter.Write(module, outputPath,
            result.CfgEmission, ilSpyDirectory, qualityReportPath,
            qualityReferenceDirectory);
        Console.WriteLine($"[*] Method quality report: {qualityReportPath} "
            + $"({qualityReport.Summary.Decompiled}/{qualityReport.Summary.Methods} "
            + "token-addressed C# methods).");
    }
    Console.WriteLine("[*] Done.");
    return 0;
}

bool lift = args.Contains("--lift");
string? liftFilter = lift ? args.SkipWhile(a => a != "--lift").Skip(1).FirstOrDefault() : dumpFilter;
ExecuteInterpreter? interp = lift
    ? new ExecuteInterpreter(module, RuntimeVocabulary.Build(runtime), RuntimeHelpers.Build(runtime), ConditionClassifier.Build(runtime))
    : null;

int ok = 0, fail = 0, methodsFullyLifted = 0;
long totalInstr = 0, liftedInstr = 0, unliftedInstr = 0;
var failures = new List<string>();
var liftGaps = new SortedDictionary<string, int>();
foreach (var m in methods)
{
    string name = (module.TryLookupMember(new MetadataToken(m.Token), out var mem) && mem is MethodDefinition md)
        ? md.FullName : $"0x{m.Token:X8}";
    string displayName = DisplayText.Escape(name);
    try
    {
        var decoded = MethodDecoder.Decode(module, runtime, m);
        if (interp is not null && mem is MethodDefinition targetMd)
            interp.BeginMethod(runtime, decoded.Instructions, decoded.Locals,
                Devirtualizer.VmArgTypes(targetMd), decoded.ExceptionHandlers);
        ok++;
        totalInstr += decoded.Instructions.Count;

        string signature = mem is MethodDefinition filterMethod
            ? filterMethod.Signature?.ToString() ?? string.Empty
            : string.Empty;
        bool show = (dump || lift) && (liftFilter is null
            || name.Contains(liftFilter, StringComparison.OrdinalIgnoreCase)
            || displayName.Contains(liftFilter, StringComparison.OrdinalIgnoreCase)
            || signature.Contains(liftFilter, StringComparison.OrdinalIgnoreCase)
            || m.Token.ToString("X8").Contains(liftFilter, StringComparison.OrdinalIgnoreCase));
        if (show)
        {
            Console.WriteLine();
            Console.WriteLine($"=== {displayName}  (token 0x{m.Token:X8}) ===");
            Console.WriteLine($"    locals ({decoded.Locals.Count}): {string.Join(", ", decoded.Locals.Select(l => l.Name))}");
        }
        bool methodFullyLifted = interp is not null;
        foreach (var instr in decoded.Instructions)
        {
            string? liftText = null;
            if (interp is not null)
            {
                var h = runtime.Handlers[instr.Opcode];
                try
                {
                    var cil = interp.Lift(h, instr);
                    liftedInstr++;
                    liftText = string.Join("; ", cil);
                }
                catch (Exception ex)
                {
                    unliftedInstr++;
                    methodFullyLifted = false;
                    string reason = ex is LiftUnsupported ? ex.Message : $"[{ex.GetType().Name}] {ex.Message}";
                    liftGaps[reason] = liftGaps.GetValueOrDefault(reason) + 1;
                    liftText = $"<unsupported: {reason}>";
                }
            }
            if (show)
                Console.WriteLine(interp is null ? $"    {instr}" : $"    {instr}\n         => {liftText}");
        }
        if (methodFullyLifted) methodsFullyLifted++;
        if (show)
            foreach (var eh in decoded.ExceptionHandlers)
                Console.WriteLine($"    EH type={eh.ClauseType} try[{eh.TryStart}..{eh.TryEnd}] " +
                                  $"handler[{eh.HandlerStart}..{eh.HandlerEnd}] extra=0x{eh.ExtraToken:X8}");
    }
    catch (Exception ex)
    {
        fail++;
        failures.Add($"    {displayName}: {ex.Message}");
        if (fail == 1 && Environment.GetEnvironmentVariable("DBG") == "1")
            Console.WriteLine("[dbg first failure]\n" + ex);
    }
}

Console.WriteLine();
Console.WriteLine($"[*] Decoded {ok}/{methods.Count} method(s), {totalInstr} instruction(s) total.");
if (interp is not null)
{
    Console.WriteLine($"[*] Lifted {liftedInstr}/{liftedInstr + unliftedInstr} instruction(s) " +
                      $"({(liftedInstr + unliftedInstr == 0 ? 0 : 100.0 * liftedInstr / (liftedInstr + unliftedInstr)):F1}%); " +
                      $"{methodsFullyLifted}/{ok} method(s) fully lifted.");
    foreach (var (reason, count) in liftGaps.OrderByDescending(kv => kv.Value).Take(20))
        Console.WriteLine($"    x{count,-4} {reason}");
}
if (fail > 0)
{
    Console.WriteLine($"[!] {fail} method(s) failed to decode:");
    foreach (var f in failures.Take(30))
        Console.WriteLine(f);
}
return fail == 0 ? 0 : 3;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[!] Unexpected error: {ex.GetType().Name}: {ex.Message}");
    if (Environment.GetEnvironmentVariable("DBG") == "1")
        Console.Error.WriteLine(ex);
    return 99;
}
