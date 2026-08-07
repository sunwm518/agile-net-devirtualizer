using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaInterferenceCoalescingResult(
    CilMethodBody Body,
    EhSsaCrossBlockCoalescingResult CrossBlockCoalescing,
    bool Optimized,
    string Reason,
    int Changes,
    int RemovedLocals);

/// <summary>
/// Fifth EH cleanup tier: merges locals whose live ranges (per <see cref="CilLocalInterferenceGraph"/>)
/// never overlap into a shared slot, regardless of whether a copy instruction connects them. This is
/// the tier that actually shrinks the "one fresh local per stack-phi/spill value" shape the EH SSA
/// shadow emitter produces by construction — cross-block copy propagation only removes pure aliases,
/// while this pass reduces the declared count for values with genuinely distinct lifetimes. Starts
/// from the independently selected cross-block-coalescing body and keeps it whenever the candidate is
/// rejected. Verifies on a fresh <see cref="CilMethodBodyCloner"/> clone for the same reason the
/// cross-block tier does: re-verifying the same instance a further time throws a spurious
/// `StackImbalanceException` in AsmResolver even with zero edits.
/// </summary>
internal static class EhSsaInterferenceCoalescingEmitter
{
    public static EhSsaInterferenceCoalescingResult EmitBest(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var installed = target.CilMethodBody;
        var fallback = EhSsaCrossBlockCoalescingEmitter.EmitBest(module, target, decoded,
            graph, plan, tempLocalTypes);
        var candidateBody = CilMethodBodyCloner.Clone(fallback.Body);
        try
        {
            int beforeLocals = candidateBody.LocalVariables.Count;
            int changes = CilInterferenceLocalCoalescing.Run(candidateBody);
            if (changes == 0)
                return Keep("no non-interfering same-type locals");

            var owner = new MethodDefinition(target.Name, target.Attributes,
                target.Signature ?? throw new InvalidOperationException("target has no signature"),
                verify: false)
            {
                CilMethodBody = candidateBody,
            };
            candidateBody.Instructions.CalculateOffsets();
            candidateBody.VerifyLabels(calculateOffsets: false);
            candidateBody.ComputeMaxStack();
            CilTypeSafetyValidator.Validate(candidateBody);
            owner.CilMethodBody = null;
            if (candidateBody.ExceptionHandlers.Count != fallback.Body.ExceptionHandlers.Count)
                return Keep("cleanup changed the EH clause count");
            if (!ReferenceEquals(target.CilMethodBody, installed))
                throw new InvalidOperationException(
                    "EH interference coalescing changed the installed target body");

            int removedLocals = beforeLocals - candidateBody.LocalVariables.Count;
            if (removedLocals < 0)
                return Keep("cleanup increased a structural metric");
            return new EhSsaInterferenceCoalescingResult(candidateBody, fallback, true,
                "verified interference-based local coalescing", changes, removedLocals);
        }
        catch (Exception exception)
        {
            return Keep($"candidate rejected ({exception.GetType().Name}: "
                + exception.Message + ")");
        }

        EhSsaInterferenceCoalescingResult Keep(string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, installed))
                target.CilMethodBody = installed;
            return new EhSsaInterferenceCoalescingResult(fallback.Body, fallback, false, reason,
                0, 0);
        }
    }
}
