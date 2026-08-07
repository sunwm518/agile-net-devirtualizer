using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Full-body liveness and interference graph for CIL locals. A local is eligible only when every
/// reference to it anywhere in the body is a plain <c>ldloc</c>/<c>stloc</c> (short or long form); a
/// local ever addressed via <c>ldloca</c> or referenced any other way has an unknown true live extent
/// and is excluded rather than guessed. Exceptional control flow is modeled conservatively: every
/// instruction inside a try region has an additional edge to its handler's entry, so a value the
/// handler could read stays live across the whole guarded region even though no real branch encodes
/// that edge; a `leave` that exits a `finally`/`fault` region is additionally chained through that
/// region's handler.
///
/// Merging is further restricted to locals whose entire live range stays inside one exception-region
/// membership signature (see <see cref="CilInstructionFlowGraph.BuildMembership"/>). The exceptional
/// and finally-chain edges above are the only implicit control-flow this graph models; more exotic
/// interactions between nested regions (e.g. a finally's own cleanup code being caught by an
/// enclosing handler) are not independently proven correct, so a local whose live range would need
/// that reasoning is excluded rather than risked.
/// </summary>
internal static class CilLocalInterferenceGraph
{
    public static HashSet<CilLocalVariable> EligibleLocals(CilMethodBody body)
    {
        var disqualified = new HashSet<CilLocalVariable>();
        var seen = new HashSet<CilLocalVariable>();
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is not CilLocalVariable local)
                continue;
            seen.Add(local);
            if (instruction.OpCode.Code is not (CilCode.Ldloc or CilCode.Ldloc_S
                or CilCode.Stloc or CilCode.Stloc_S))
                disqualified.Add(local);
        }
        seen.ExceptWith(disqualified);
        return seen;
    }

    /// <summary>
    /// Narrows <paramref name="eligible"/> to locals whose live range never crosses from one exception-
    /// region membership signature into another. A local live at two positions with different
    /// memberships is excluded outright, rather than trusting the exceptional/finally-chain edges to
    /// have modeled every possible interaction correctly.
    /// </summary>
    public static HashSet<CilLocalVariable> ConfinedEligibleLocals(
        CilMethodBody body,
        IReadOnlySet<CilLocalVariable> eligible)
    {
        var indexOf = CilInstructionFlowGraph.IndexInstructions(body);
        var successors = CilInstructionFlowGraph.BuildSuccessors(body, indexOf,
            includeExceptionEdges: true);
        var liveIn = ComputeLiveIn(body, successors, eligible);
        var membership = CilInstructionFlowGraph.BuildMembership(body, indexOf);

        var reference = new Dictionary<CilLocalVariable, HashSet<(int, int)>>();
        var crossRegion = new HashSet<CilLocalVariable>();

        void Check(CilLocalVariable local, int position)
        {
            if (crossRegion.Contains(local))
                return;
            if (!reference.TryGetValue(local, out var signature))
                reference[local] = membership[position];
            else if (!signature.SetEquals(membership[position]))
                crossRegion.Add(local);
        }

        for (int position = 0; position < body.Instructions.Count; position++)
        {
            foreach (var local in liveIn[position])
                Check(local, position);
            var instruction = body.Instructions[position];
            if (instruction.Operand is CilLocalVariable stored && eligible.Contains(stored)
                && instruction.OpCode.Code is CilCode.Stloc or CilCode.Stloc_S)
                Check(stored, position);
        }

        var confined = new HashSet<CilLocalVariable>(eligible);
        confined.ExceptWith(crossRegion);
        return confined;
    }

    public static IReadOnlyDictionary<CilLocalVariable, HashSet<CilLocalVariable>> Build(
        CilMethodBody body,
        IReadOnlySet<CilLocalVariable> eligible)
    {
        var indexOf = CilInstructionFlowGraph.IndexInstructions(body);
        var successors = CilInstructionFlowGraph.BuildSuccessors(body, indexOf,
            includeExceptionEdges: true);
        var liveIn = ComputeLiveIn(body, successors, eligible);

        var graph = new Dictionary<CilLocalVariable, HashSet<CilLocalVariable>>();
        foreach (var local in eligible)
            graph[local] = [];
        foreach (var liveSet in liveIn)
        {
            if (liveSet.Count < 2)
                continue;
            var locals = liveSet.ToArray();
            for (int a = 0; a < locals.Length; a++)
            for (int b = a + 1; b < locals.Length; b++)
            {
                graph[locals[a]].Add(locals[b]);
                graph[locals[b]].Add(locals[a]);
            }
        }
        return graph;
    }

    /// <summary>
    /// Classical backward dataflow (`live_in = use ∪ (live_out - def)`) computed directly at
    /// instruction granularity rather than per-block, since a single instruction is unambiguously
    /// either a load (use) or a store (def) of at most one eligible local — this avoids a separate
    /// block-level use/def aggregation step while staying exact.
    /// </summary>
    private static HashSet<CilLocalVariable>[] ComputeLiveIn(
        CilMethodBody body,
        Dictionary<int, List<int>> successors,
        IReadOnlySet<CilLocalVariable> eligible)
    {
        int count = body.Instructions.Count;
        var liveIn = new HashSet<CilLocalVariable>[count];
        var liveOut = new HashSet<CilLocalVariable>[count];
        for (int index = 0; index < count; index++)
        {
            liveIn[index] = [];
            liveOut[index] = [];
        }

        bool changed;
        do
        {
            changed = false;
            for (int index = count - 1; index >= 0; index--)
            {
                HashSet<CilLocalVariable>? newOut = null;
                if (successors.TryGetValue(index, out var succs) && succs.Count > 0)
                {
                    newOut = [];
                    foreach (int successor in succs)
                        newOut.UnionWith(liveIn[successor]);
                }
                newOut ??= [];
                if (!newOut.SetEquals(liveOut[index]))
                {
                    liveOut[index] = newOut;
                    changed = true;
                }

                var newIn = new HashSet<CilLocalVariable>(liveOut[index]);
                var instruction = body.Instructions[index];
                if (instruction.Operand is CilLocalVariable local && eligible.Contains(local))
                {
                    if (instruction.OpCode.Code is CilCode.Stloc or CilCode.Stloc_S)
                        newIn.Remove(local);
                    else if (instruction.OpCode.Code is CilCode.Ldloc or CilCode.Ldloc_S)
                        newIn.Add(local);
                }
                if (!newIn.SetEquals(liveIn[index]))
                {
                    liveIn[index] = newIn;
                    changed = true;
                }
            }
        } while (changed);

        return liveIn;
    }
}
