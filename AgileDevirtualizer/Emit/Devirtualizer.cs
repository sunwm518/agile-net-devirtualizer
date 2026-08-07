using AgileDevirtualizer.Analysis;
using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Diagnostics;
using AgileDevirtualizer.Lift;
using AgileDevirtualizer.Resource;
using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Emit;

internal sealed record DevirtResult(
    int Total,
    int Devirtualized,
    List<string> Failures,
    CfgEmissionSummary CfgEmission);

/// <summary>
/// Drives devirtualization: for every entry in the <c>_CSVM</c> table, decode and lift the method;
/// if every instruction lifted, rebuild its body and swap it in. Methods with any unlifted
/// instruction are left virtualized (partial, honest output) and reported.
/// </summary>
internal static class Devirtualizer
{
    public static DevirtResult Run(ModuleDefinition module, RuntimeModel runtime, List<VMMethod> methods,
                                   ExecuteInterpreter interp, IReadOnlySet<uint>? excludedTokens = null,
                                   bool useSemanticEmission = true,
                                   bool optimizeSemanticEmission = true,
                                   bool enableTypedSsa = false,
                                   bool enablePhiSsa = false,
                                   bool enableEdgeSsaShadow = false,
                                   bool enableEhSsaValidationArtifact = false,
                                   bool enableEhSsaCopyValidationArtifact = false,
                                   bool enableEhSsa = true,
                                   bool enableRedundantCastShadow = false,
                                   bool enableRedundantCastCleanup = false)
    {
        int devirt = 0;
        var failures = new List<string>();
        var cfgEmission = new CfgEmissionSummary(useSemanticEmission);

        foreach (var vm in methods)
        {
            if (excludedTokens?.Contains(vm.Token) == true)
            {
                failures.Add($"0x{vm.Token:X8}: excluded by request; kept VM-backed");
                continue;
            }

            if (!module.TryLookupMember(new MetadataToken(vm.Token), out var member) || member is not MethodDefinition target)
            {
                failures.Add($"0x{vm.Token:X8}: token does not resolve to a method");
                continue;
            }

            LiftDiagnosticSession? diagnostics = null;
            try
            {
                var decoded = MethodDecoder.Decode(module, runtime, vm);
                diagnostics = LiftDiagnosticSession.TryCreate(target, decoded);
                interp.BeginMethod(runtime, decoded.Instructions, decoded.Locals, VmArgTypes(target),
                    decoded.ExceptionHandlers);
                var lifted = new List<List<LiftedOp>>(decoded.Instructions.Count);
                var stateSnapshots = diagnostics is null ? null : new List<string>();
                var legacySnapshots = diagnostics is null ? null : new List<LegacyStateSnapshot>();
                string? gap = null;
                foreach (var instr in decoded.Instructions)
                {
                    try
                    {
                        lifted.Add(interp.Lift(runtime.Handlers[instr.Opcode], instr));
                        stateSnapshots?.Add($"VM #{instr.Index:D4}: {interp.DescribeDiagnosticState()}");
                        legacySnapshots?.Add(interp.CaptureLegacyState(instr.Index));
                    }
                    catch (Exception ex)
                    {
                        gap ??= ex is LiftUnsupported ? ex.Message : ex.GetType().Name;
                        stateSnapshots?.Add($"VM #{instr.Index:D4}: ERROR={gap} "
                            + interp.DescribeDiagnosticState());
                        break;
                    }
                }
                diagnostics?.WriteLifted(decoded, lifted, gap, stateSnapshots ?? [],
                    legacySnapshots ?? []);

                if (gap is not null)
                {
                    diagnostics?.WriteStatus("Unsupported: " + gap);
                    failures.Add($"0x{vm.Token:X8} {target.Name}: not fully lifted ({gap})");
                    continue;
                }

                // Build validates the body (ComputeMaxStack) and swaps it into `target` only once it
                // verifies, rolling back to the original body on failure â€” so a rejected method
                // stays virtualized rather than broken.
                try
                {
                    CilMethodBody body;
                    string status;
                    if (useSemanticEmission)
                    {
                        bool validateAllEh = enableEhSsaValidationArtifact
                            && decoded.ExceptionHandlers.Count > 0;
                        bool validateCopyEh = enableEhSsaCopyValidationArtifact
                            && decoded.ExceptionHandlers.Count > 0;
                        bool tryStrictEh = enableEhSsa && optimizeSemanticEmission
                            && !validateAllEh && !validateCopyEh
                            && decoded.ExceptionHandlers.Count > 0;
                        CfgEmissionDecision? ehDecision = null;
                        if (validateAllEh || validateCopyEh || tryStrictEh)
                        {
                            var selection = validateAllEh
                                ? EhSsaValidationSelection.AllVerified
                                : validateCopyEh
                                    ? EhSsaValidationSelection.RuntimeProvenOrSameRegionEdgeCopies
                                    : EhSsaValidationSelection.RuntimeProven;
                            ehDecision = EhSsaValidationEmissionController.TryActivate(
                                module, target, decoded, lifted, interp.TempLocalTypes,
                                selection, enableRedundantCastShadow,
                                enableRedundantCastCleanup);
                        }
                        bool installedEh = ehDecision?.Outcome == CfgEmissionOutcome.Activated;
                        var decision = validateAllEh || installedEh
                            ? ehDecision!
                            : SemanticEmissionController.TryActivate(module, target,
                                decoded, lifted, interp.TempLocalTypes,
                                optimize: optimizeSemanticEmission,
                                enableTypedSsa: enableTypedSsa,
                                enablePhiSsa: enablePhiSsa,
                                enableEdgeSsaShadow: enableEdgeSsaShadow,
                                enableRedundantCastShadow: enableRedundantCastShadow,
                                enableRedundantCastCleanup: enableRedundantCastCleanup);
                        if (tryStrictEh && !installedEh
                            && decision.Outcome == CfgEmissionOutcome.Activated)
                            decision = decision with { Reason = decision.Reason
                                + $"; strict EH SSA skipped ({ehDecision!.Reason})" };
                        cfgEmission.Record(vm.Token, $"0x{vm.Token:X8} {target.Name}", decision);
                        if (decision.Outcome != CfgEmissionOutcome.Activated)
                        {
                            status = $"Rejected: semantic emission {decision.Outcome} "
                                + $"({decision.Reason})";
                            diagnostics?.WriteStatus(status);
                            failures.Add($"0x{vm.Token:X8} {target.Name}: "
                                + $"semantic emission rejected ({decision.Reason})");
                            continue;
                        }
                        body = target.CilMethodBody
                            ?? throw new InvalidOperationException(
                                "semantic emission reported success without an installed body");
                        status = installedEh
                            ? $"Accepted: {(validateAllEh ? "validation-only" :
                                validateCopyEh ? "edge-copy validation" : "strict opt-in")} "
                                + $"EH SSA body ({decision.Features})"
                            : $"Accepted: independent Semantic IR body ({decision.Features})";
                    }
                    else
                    {
                        // Explicit rollback mode. CilBuilder validates and installs only after the
                        // legacy body passes max-stack and type-safety checks.
                        body = CilBuilder.Build(module, runtime.Module, target, decoded, lifted,
                            interp.TempLocalTypes);
                        status = "Accepted: explicit legacy emission and internal validation passed";
                    }
                    diagnostics?.WriteEmitted(body);
                    diagnostics?.WriteStatus(status);
                    devirt++;
                }
                catch (Exception ex)
                {
                    diagnostics?.WriteStatus($"Rejected: {ex.GetType().Name}: {ex.Message}");
                    failures.Add($"0x{vm.Token:X8} {target.Name}: rejected ({ex.GetType().Name}: {ex.Message})");
                    if (Environment.GetEnvironmentVariable("DBG_DEVIRT") == vm.Token.ToString("X8"))
                        Console.Error.WriteLine(ex);
                }
            }
            catch (Exception ex)
            {
                diagnostics?.WriteStatus($"Failed: {ex.GetType().Name}: {ex.Message}");
                failures.Add($"0x{vm.Token:X8} {target.Name}: {ex.Message}");
            }
        }

        return new DevirtResult(methods.Count, devirt, failures, cfgEmission);
    }

    public static bool SupportsFullTokenPreservation(ModuleDefinition module) =>
        !HasNestedTypeBeforeEnclosingType(module);

    public static void Write(ModuleDefinition module, string outputPath) =>
        Write(module, outputPath, SupportsFullTokenPreservation(module));

    public static void Write(ModuleDefinition module, string outputPath, bool preserveAllTokens)
    {
        // VM bytecode embeds raw metadata tokens from the protected module. If any method remains
        // virtualized, those tokens must keep resolving to the exact same rows after the module is
        // rebuilt. The default builder is free to reorder/deduplicate tables and heaps, which made
        // TestCases' rejected VM stub throw CSVMRuntimeException. Preserve existing indices while
        // appending any genuinely new imports required by successfully rebuilt method bodies.
        //
        // A few protected modules put a nested TypeDef before its enclosing row. AsmResolver cannot
        // preserve that impossible discovery order, and preserving only a subset of definition tables
        // corrupts their ownership ranges. Use its coherent default rebuild for that layout; a future
        // VM-resource token-remap pass is required for full raw-token preservation on those modules.
        var flags = MetadataPreservationPolicy.ForPartialRewrite(preserveAllTokens);
        if (NativeResourceSanitizer.RemoveMalformedDirectory(module))
            Console.WriteLine("[writer] dropped an unparseable native-resource directory.");
        module.Write(outputPath, new ManagedPEImageBuilder(flags));
    }

    private static bool HasNestedTypeBeforeEnclosingType(ModuleDefinition module)
    {
        foreach (var type in module.GetAllTypes())
        {
            if (type.DeclaringType is not { } parent)
                continue;
            var childToken = type.MetadataToken;
            var parentToken = parent.MetadataToken;
            if (childToken.Table == TableIndex.TypeDef && parentToken.Table == TableIndex.TypeDef
                && childToken.Rid != 0 && parentToken.Rid > childToken.Rid)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Writes a protected target assembly without perturbing it when no method was accepted. Failed
    /// build attempts can still have caused importers to stage metadata members before the method body
    /// was rolled back, so serializing the in-memory module is not a semantic no-op. A byte-for-byte
    /// copy is the only honest output for a zero-success run.
    /// </summary>
    public static void WriteTarget(ModuleDefinition module, string inputPath, string outputPath, int devirtualized,
                                   bool? preserveAllTokens = null)
    {
        if (devirtualized > 0)
        {
            Write(module, outputPath, preserveAllTokens ?? SupportsFullTokenPreservation(module));
            return;
        }

        string inputFullPath = Path.GetFullPath(inputPath);
        string outputFullPath = Path.GetFullPath(outputPath);
        if (!string.Equals(inputFullPath, outputFullPath, StringComparison.OrdinalIgnoreCase))
            File.Copy(inputFullPath, outputFullPath, overwrite: true);
    }

    /// <summary>
    /// The VM's argument-slot types: arg0 is the declaring type when the method is an instance
    /// method (the implicit `this`), followed by the method's own declared parameter types â€” the
    /// same slot layout <c>CilBuilder.Arg</c> uses to map a VM arg index back to a real parameter.
    /// </summary>
    public static IReadOnlyList<TypeSignature> VmArgTypes(MethodDefinition target)
    {
        var list = new List<TypeSignature>();
        if (!target.IsStatic && target.DeclaringType is { } dt)
            list.Add(dt.ToTypeSignature(dt.IsValueType));
        if (target.Signature is { } sig)
            list.AddRange(sig.ParameterTypes);
        return list;
    }
}
