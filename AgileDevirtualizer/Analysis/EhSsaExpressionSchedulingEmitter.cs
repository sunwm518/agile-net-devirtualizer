using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record EhSsaExpressionSchedulingResult(
    CilMethodBody Body,
    EhSsaLocalCoalescingResult LocalCoalescing,
    bool Optimized,
    string Reason,
    int ForwardedValues,
    int RemovedInstructions,
    int RemovedLocals);

/// <summary>
/// Detached fail-closed EH expression scheduling. It starts from the independently selected local
/// coalescing body and preserves that body if stack/type validation rejects expression forwarding.
/// </summary>
internal static class EhSsaExpressionSchedulingEmitter
{
    public static EhSsaExpressionSchedulingResult EmitBest(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        EhSsaShadowPlan plan,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var fallback = EhSsaLocalCoalescingEmitter.EmitBest(module, target, decoded,
            graph, plan, tempLocalTypes);
        var candidate = EhSsaLocalCoalescingEmitter.EmitBest(module, target, decoded,
            graph, plan, tempLocalTypes);
        try
        {
            var forwarding = CilSingleUseExpressionForwarder.Run(candidate.Body);
            if (forwarding.ForwardedValues == 0)
                return Keep("no adjacent single-use values");
            candidate.Body.Instructions.CalculateOffsets();
            candidate.Body.VerifyLabels(calculateOffsets: false);
            candidate.Body.ComputeMaxStack();
            CilTypeSafetyValidator.Validate(candidate.Body);
            return new EhSsaExpressionSchedulingResult(candidate.Body,
                candidate, true, "verified adjacent EH expression forwarding",
                forwarding.ForwardedValues, forwarding.RemovedInstructions,
                forwarding.RemovedLocals);
        }
        catch (Exception exception)
        {
            return Keep($"candidate rejected ({exception.GetType().Name}: "
                + exception.Message + ")");
        }

        EhSsaExpressionSchedulingResult Keep(string reason) => new(fallback.Body,
            fallback, false, reason, 0, 0, 0);
    }
}
