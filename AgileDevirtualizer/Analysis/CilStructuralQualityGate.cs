using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

internal sealed record CilStructuralQuality(
    int Instructions,
    int Locals,
    int Casts,
    int Aliases,
    int BasicBlocks,
    int Spills)
{
    // These weights measure decompiler scaffolding, not runtime cost. Locals, explicit casts and
    // copy aliases usually survive into C# and are therefore more expensive than a single CIL op.
    public int Cost => checked(Instructions + Locals * 3 + Casts * 4
        + Aliases * 5 + BasicBlocks * 2 + Spills * 4);

    public override string ToString() =>
        $"i{Instructions}/l{Locals}/c{Casts}/a{Aliases}/b{BasicBlocks}/s{Spills}/q{Cost}";
}

internal sealed record CilStructuralQualityDecision(
    bool Better,
    CilStructuralQuality Baseline,
    CilStructuralQuality Candidate,
    string Reason)
{
    public string Summary => $"{Baseline}->{Candidate}";
}

/// <summary>
/// Deterministic production selector for independently verified CIL bodies. A candidate may be a
/// few instructions larger when it removes enough decompiler-visible scaffolding, but unbounded
/// growth is rejected regardless of its weighted score.
/// </summary>
internal static class CilStructuralQualityGate
{
    public static CilStructuralQualityDecision Evaluate(CilMethodBody baseline,
        int baselineSpills, CilMethodBody candidate, int candidateSpills)
    {
        var before = Measure(baseline, baselineSpills);
        var after = Measure(candidate, candidateSpills);
        int growthAllowance = Math.Max(4, (before.Instructions + 19) / 20);
        if (after.Instructions > before.Instructions + growthAllowance)
            return new CilStructuralQualityDecision(false, before, after,
                $"instruction growth exceeds +{growthAllowance}");
        if (after.Cost >= before.Cost)
            return new CilStructuralQualityDecision(false, before, after,
                after.Cost == before.Cost ? "equal structural cost" : "higher structural cost");
        return new CilStructuralQualityDecision(true, before, after,
            after.Instructions > before.Instructions
                ? "bounded CIL growth buys lower structural debt"
                : "lower structural cost");
    }

    public static CilStructuralQuality Measure(CilMethodBody body, int spills = 0)
    {
        if (spills < 0)
            throw new ArgumentOutOfRangeException(nameof(spills));
        return new CilStructuralQuality(body.Instructions.Count,
            body.LocalVariables.Count, CountCasts(body), CountAliases(body),
            CountBasicBlocks(body), spills);
    }

    private static int CountCasts(CilMethodBody body) => body.Instructions.Count(instruction =>
        instruction.OpCode.Code is CilCode.Castclass or CilCode.Isinst or CilCode.Box
            or CilCode.Unbox or CilCode.Unbox_Any);

    private static int CountAliases(CilMethodBody body)
    {
        int aliases = 0;
        for (int index = 1; index < body.Instructions.Count; index++)
        {
            if (!IsStoreLocal(body, index))
                continue;
            int source = index - 1;
            if (body.Instructions[source].OpCode.Code == CilCode.Castclass)
                source--;
            if (source >= 0 && (IsLoadLocal(body, source)
                || IsLoadArgument(body.Instructions[source])))
                aliases++;
        }
        return aliases;
    }

    private static int CountBasicBlocks(CilMethodBody body)
    {
        if (body.Instructions.Count == 0)
            return 0;
        body.Instructions.CalculateOffsets();
        var starts = new HashSet<int> { 0 };
        for (int index = 0; index < body.Instructions.Count; index++)
        {
            var instruction = body.Instructions[index];
            if (instruction.Operand is ICilLabel label)
                AddLabel(label);
            else if (instruction.Operand is IList<ICilLabel> labels)
                foreach (var target in labels)
                    AddLabel(target);
            if (index + 1 < body.Instructions.Count
                && instruction.OpCode.FlowControl is CilFlowControl.Branch
                    or CilFlowControl.ConditionalBranch or CilFlowControl.Return
                    or CilFlowControl.Throw)
                starts.Add(index + 1);
        }
        foreach (var handler in body.ExceptionHandlers)
        {
            AddLabel(handler.TryStart);
            AddLabel(handler.TryEnd);
            AddLabel(handler.HandlerStart);
            AddLabel(handler.HandlerEnd);
            AddLabel(handler.FilterStart);
        }
        return starts.Count;

        void AddLabel(ICilLabel? label)
        {
            if (label is null)
                return;
            if (label is CilInstructionLabel { Instruction: { } target })
            {
                for (int index = 0; index < body.Instructions.Count; index++)
                {
                    if (ReferenceEquals(body.Instructions[index], target))
                    {
                        starts.Add(index);
                        return;
                    }
                }
            }
            for (int index = 0; index < body.Instructions.Count; index++)
            {
                if (body.Instructions[index].Offset == label.Offset)
                {
                    starts.Add(index);
                    return;
                }
            }
        }
    }

    private static bool IsStoreLocal(CilMethodBody body, int index) =>
        body.Instructions[index].OpCode.Code is CilCode.Stloc or CilCode.Stloc_S
            or CilCode.Stloc_0 or CilCode.Stloc_1 or CilCode.Stloc_2 or CilCode.Stloc_3;

    private static bool IsLoadLocal(CilMethodBody body, int index) =>
        body.Instructions[index].OpCode.Code is CilCode.Ldloc or CilCode.Ldloc_S
            or CilCode.Ldloc_0 or CilCode.Ldloc_1 or CilCode.Ldloc_2 or CilCode.Ldloc_3;

    private static bool IsLoadArgument(CilInstruction instruction) =>
        instruction.OpCode.Code is CilCode.Ldarg or CilCode.Ldarg_S or CilCode.Ldarg_0
            or CilCode.Ldarg_1 or CilCode.Ldarg_2 or CilCode.Ldarg_3;
}
