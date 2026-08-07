using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Decides whether forwarding a copy across basic blocks is safe. The copy definition and every load
/// of the destination must sit in the exact same exception-region nesting (this deliberately never
/// models `leave`/`endfinally`/`endfilter` continuations), and no dynamic path from the definition to
/// a load may pass through a redefinition of the source local. Both checks fail closed: an
/// unrecognized shape or an unreachable load rejects the whole candidate.
/// </summary>
internal static class CrossBlockPropagationLegality
{
    public static bool IsSafe(
        CilMethodBody body,
        CilLocalVariable source,
        int storeIndex,
        IEnumerable<int> loadPositions)
    {
        var loads = loadPositions.ToArray();
        var indexOf = CilInstructionFlowGraph.IndexInstructions(body);
        var membership = CilInstructionFlowGraph.BuildMembership(body, indexOf);
        var required = membership[storeIndex];
        if (loads.Any(load => !membership[load].SetEquals(required)))
            return false;

        var successors = BuildSuccessors(body, indexOf, membership, required);
        var (reachable, tainted) = Explore(storeIndex, successors, position =>
            IsStoreOf(body.Instructions[position], source));
        return loads.All(load => reachable.Contains(load) && !tainted.Contains(load));
    }

    private static bool IsStoreOf(CilInstruction instruction, CilLocalVariable local) =>
        instruction.OpCode.Code is CilCode.Stloc or CilCode.Stloc_S
        && ReferenceEquals(instruction.Operand, local);

    private static Dictionary<int, List<int>> BuildSuccessors(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf,
        Dictionary<int, HashSet<(int Clause, int Zone)>> membership,
        HashSet<(int Clause, int Zone)> required)
    {
        var raw = CilInstructionFlowGraph.BuildSuccessors(body, indexOf,
            includeExceptionEdges: false);
        var successors = new Dictionary<int, List<int>>();
        foreach (int position in raw.Keys)
        {
            if (!membership[position].SetEquals(required))
                continue;
            successors[position] = raw[position]
                .Where(candidate => membership[candidate].SetEquals(required)).ToList();
        }
        return successors;
    }

    /// <summary>
    /// Forward search from <paramref name="start"/>. <paramref name="reachable"/> is every position
    /// reached by any path; <paramref name="tainted"/> is every position reached by at least one path
    /// that already passed a barrier (a redefinition of the source). A position visited both cleanly
    /// and taintedly is tracked in both sets, since only one dynamic path needs to be unsafe.
    /// </summary>
    private static (HashSet<int> Reachable, HashSet<int> Tainted) Explore(
        int start,
        Dictionary<int, List<int>> successors,
        Func<int, bool> isBarrier)
    {
        var reachable = new HashSet<int>();
        var tainted = new HashSet<int>();
        var visited = new HashSet<(int Position, bool Tainted)>();
        var queue = new Queue<(int Position, bool Tainted)>();
        Enqueue(start, false);

        while (queue.Count > 0)
        {
            var (position, isTainted) = queue.Dequeue();
            reachable.Add(position);
            if (isTainted)
                tainted.Add(position);
            bool nextTainted = isTainted || isBarrier(position);
            if (successors.TryGetValue(position, out var succs))
                foreach (int next in succs)
                    Enqueue(next, nextTainted);
        }
        return (reachable, tainted);

        void Enqueue(int position, bool isTainted)
        {
            if (visited.Add((position, isTainted)))
                queue.Enqueue((position, isTainted));
        }
    }
}
