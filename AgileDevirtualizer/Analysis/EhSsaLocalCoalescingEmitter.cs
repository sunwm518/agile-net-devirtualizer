using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaLocalCoalescingResult(
    CilMethodBody Body,
    bool Optimized,
    string Reason,
    int Changes,
    int RemovedInstructions,
    int RemovedLocals,
    int RemovedCasts);

/// <summary>
/// Applies the single-basic-block local propagation tier to a separately emitted EH body. The
/// original verified EH SSA body is retained whenever cleanup or any verifier rejects the
/// candidate; neither body is installed by this component.
/// </summary>
internal static class EhSsaLocalCoalescingEmitter
{
    public static EhSsaLocalCoalescingResult EmitBest(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var installed = target.CilMethodBody;
        var baseline = EhSsaShadowEmitter.Emit(module, target, decoded, graph, plan,
            tempLocalTypes);
        try
        {
            var candidate = EhSsaShadowEmitter.Emit(module, target, decoded, graph, plan,
                tempLocalTypes);
            int beforeInstructions = candidate.Instructions.Count;
            int beforeLocals = candidate.LocalVariables.Count;
            int beforeCasts = CountCasts(candidate);
            int changes = CilLocalCleanup.RunEhSafe(candidate);
            if (changes == 0)
                return Baseline("no single-block aliases");

            candidate.Instructions.CalculateOffsets();
            candidate.VerifyLabels(calculateOffsets: false);
            candidate.ComputeMaxStack();
            CilTypeSafetyValidator.Validate(candidate);
            if (candidate.ExceptionHandlers.Count != baseline.ExceptionHandlers.Count)
                return Baseline("cleanup changed the EH clause count");
            if (!ReferenceEquals(target.CilMethodBody, installed))
                throw new InvalidOperationException(
                    "EH local coalescing changed the installed target body");

            int removedInstructions = beforeInstructions - candidate.Instructions.Count;
            int removedLocals = beforeLocals - candidate.LocalVariables.Count;
            int removedCasts = beforeCasts - CountCasts(candidate);
            if (removedInstructions < 0 || removedLocals < 0 || removedCasts < 0)
                return Baseline("cleanup increased a structural metric");
            return new EhSsaLocalCoalescingResult(candidate, true,
                "verified single-basic-block EH local coalescing", changes,
                removedInstructions, removedLocals, removedCasts);
        }
        catch (Exception exception)
        {
            return Baseline($"candidate rejected ({exception.GetType().Name}: "
                + exception.Message + ")");
        }

        EhSsaLocalCoalescingResult Baseline(string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, installed))
                target.CilMethodBody = installed;
            return new EhSsaLocalCoalescingResult(baseline, false, reason,
                0, 0, 0, 0);
        }
    }

    private static int CountCasts(CilMethodBody body) => body.Instructions.Count(instruction =>
        instruction.OpCode.Code == CilCode.Castclass);
}
