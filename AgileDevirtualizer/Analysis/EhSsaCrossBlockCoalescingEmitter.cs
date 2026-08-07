using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaCrossBlockCoalescingResult(
    CilMethodBody Body,
    EhSsaExpressionSchedulingResult ExpressionScheduling,
    bool Optimized,
    string Reason,
    int Changes,
    int RemovedInstructions,
    int RemovedLocals);

/// <summary>
/// Third EH cleanup tier: forwards copies whose definition and every load cross a basic-block
/// boundary, once <see cref="CrossBlockPropagationLegality"/> proves every load stays inside the same
/// exception-region nesting and cannot be reached through a redefinition of the source. Starts from
/// the independently selected expression-scheduling body and keeps it whenever the candidate is
/// rejected by verification.
///
/// The candidate is built on a fresh <see cref="CilMethodBodyCloner"/> clone, never on the
/// expression-scheduling body itself: that body already had `ComputeMaxStack` run twice internally
/// (once inside local coalescing, once inside expression scheduling), and a third call on the same
/// instance throws a spurious `StackImbalanceException` even with zero further edits. Verifying a
/// fresh clone instead sidesteps that AsmResolver-side non-idempotency, matching the pattern already
/// used by <see cref="CilRedundantCastShadowEmitter"/>.
/// </summary>
internal static class EhSsaCrossBlockCoalescingEmitter
{
    public static EhSsaCrossBlockCoalescingResult EmitBest(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var installed = target.CilMethodBody;
        var fallback = EhSsaExpressionSchedulingEmitter.EmitBest(module, target, decoded,
            graph, plan, tempLocalTypes);
        var candidateBody = CilMethodBodyCloner.Clone(fallback.Body);
        try
        {
            int beforeInstructions = candidateBody.Instructions.Count;
            int beforeLocals = candidateBody.LocalVariables.Count;
            int changes = CilCrossBlockCopyPropagation.Run(candidateBody);
            if (changes == 0)
                return Keep("no cross-block copy candidates");

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
                    "EH cross-block coalescing changed the installed target body");

            int removedInstructions = beforeInstructions - candidateBody.Instructions.Count;
            int removedLocals = beforeLocals - candidateBody.LocalVariables.Count;
            if (removedInstructions < 0 || removedLocals < 0)
                return Keep("cleanup increased a structural metric");
            return new EhSsaCrossBlockCoalescingResult(candidateBody, fallback, true,
                "verified cross-block EH copy propagation", changes,
                removedInstructions, removedLocals);
        }
        catch (Exception exception)
        {
            return Keep($"candidate rejected ({exception.GetType().Name}: "
                + exception.Message + ")");
        }

        EhSsaCrossBlockCoalescingResult Keep(string reason)
        {
            if (!ReferenceEquals(target.CilMethodBody, installed))
                target.CilMethodBody = installed;
            return new EhSsaCrossBlockCoalescingResult(fallback.Body, fallback, false, reason,
                0, 0, 0);
        }
    }
}
