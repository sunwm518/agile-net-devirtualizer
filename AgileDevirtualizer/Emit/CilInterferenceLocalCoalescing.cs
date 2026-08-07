using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Merges CIL locals that never interfere into a shared slot, independent of any copy instruction
/// between them. Two locals may share a slot only when their declared types are identical, their live
/// ranges (per <see cref="CilLocalInterferenceGraph"/>) never overlap at any instruction, and neither
/// one's live range crosses from one exception-region membership into another
/// (<see cref="CilLocalInterferenceGraph.ConfinedEligibleLocals"/>) — merges spanning regions depend on
/// implicit control flow (`leave`/`endfinally` chains, nested-region interactions) that is only proven
/// correct for the specific shapes this graph models, so a local needing more than that is excluded
/// rather than risked. A local ever addressed via <c>ldloca</c> is excluded entirely too. This is plain
/// register-style coalescing, complementary to <see cref="CilCrossBlockCopyPropagation"/>: that pass
/// removes a copy outright when the destination is a pure alias, while this pass only reduces the
/// declared local count for values with genuinely distinct, non-overlapping lifetimes.
/// </summary>
internal static class CilInterferenceLocalCoalescing
{
    public static int Run(CilMethodBody body)
    {
        var eligible = CilLocalInterferenceGraph.EligibleLocals(body);
        if (eligible.Count < 2)
            return CilLocalCleanup.RemoveUnusedLocals(body);
        var confined = CilLocalInterferenceGraph.ConfinedEligibleLocals(body, eligible);
        if (confined.Count < 2)
            return CilLocalCleanup.RemoveUnusedLocals(body);
        var interference = CilLocalInterferenceGraph.Build(body, confined);

        var union = new UnionFind();
        var members = new Dictionary<CilLocalVariable, HashSet<CilLocalVariable>>();
        foreach (var local in confined)
            members[local] = [local];

        var ordered = confined.OrderBy(local => body.LocalVariables.IndexOf(local)).ToArray();
        foreach (var a in ordered)
        foreach (var b in ordered)
        {
            if (ReferenceEquals(a, b))
                continue;
            var reprA = union.Find(a);
            var reprB = union.Find(b);
            if (ReferenceEquals(reprA, reprB))
                continue;
            if (reprA.VariableType.FullName != reprB.VariableType.FullName)
                continue;
            if (Interferes(members[reprA], members[reprB], interference))
                continue;
            var combined = new HashSet<CilLocalVariable>(members[reprA]);
            combined.UnionWith(members[reprB]);
            var newRepr = union.Union(reprA, reprB);
            members[newRepr] = combined;
        }

        var replacement = new Dictionary<CilLocalVariable, CilLocalVariable>();
        foreach (var local in ordered)
        {
            var repr = union.Find(local);
            if (!ReferenceEquals(local, repr))
                replacement[local] = repr;
        }
        if (replacement.Count == 0)
            return CilLocalCleanup.RemoveUnusedLocals(body);

        int changes = 0;
        foreach (var instruction in body.Instructions)
        {
            if (instruction.Operand is CilLocalVariable local
                && replacement.TryGetValue(local, out var repr))
            {
                instruction.Operand = repr;
                changes++;
            }
        }
        changes += RemoveRedundantSelfStores(body);
        changes += CilLocalCleanup.RemoveUnusedLocals(body);
        return changes;
    }

    private static bool Interferes(
        HashSet<CilLocalVariable> classA,
        HashSet<CilLocalVariable> classB,
        IReadOnlyDictionary<CilLocalVariable, HashSet<CilLocalVariable>> interference)
    {
        foreach (var member in classA)
            if (interference[member].Overlaps(classB))
                return true;
        return false;
    }

    /// <summary>
    /// After remapping, a copy whose source and destination now share a slot reads back exactly what
    /// it just wrote (`ldloc X; [castclass X's own type;] stloc X`) — a true no-op, safe to delete
    /// unconditionally. Neither instruction can throw (a redundant same-type `castclass` never rejects
    /// its own type, including null) and the net stack/local effect is zero either way. The
    /// intervening cast is common here specifically because coalescing unifies a slot that used to be
    /// two locals of two related types, one narrowed into the other by a cast that is now a same-type
    /// no-op — unlike <see cref="CilLocalCleanup"/>'s single-block tier, this needs no cross-block
    /// reasoning at all, since deleting a true no-op changes nothing regardless of control flow.
    /// </summary>
    private static int RemoveRedundantSelfStores(CilMethodBody body)
    {
        int removed = 0;
        for (int index = body.Instructions.Count - 2; index >= 0; index--)
        {
            var load = body.Instructions[index];
            if (load.OpCode.Code is not (CilCode.Ldloc or CilCode.Ldloc_S)
                || load.Operand is not CilLocalVariable loaded)
                continue;
            int storeIndex = index + 1;
            if (body.Instructions[storeIndex].OpCode.Code == CilCode.Castclass)
            {
                if (body.Instructions[storeIndex].Operand is not ITypeDescriptor cast
                    || cast.FullName != loaded.VariableType.FullName)
                    continue;
                storeIndex++;
            }
            if (storeIndex >= body.Instructions.Count)
                continue;
            var store = body.Instructions[storeIndex];
            if (store.OpCode.Code is not (CilCode.Stloc or CilCode.Stloc_S)
                || !ReferenceEquals(store.Operand, loaded))
                continue;
            if (CilLocalCleanup.IsProtected(body, index, storeIndex))
                continue;
            for (int remove = storeIndex; remove >= index; remove--)
                body.Instructions.RemoveAt(remove);
            removed++;
        }
        return removed;
    }

    private sealed class UnionFind
    {
        private readonly Dictionary<CilLocalVariable, CilLocalVariable> _parent = [];

        public CilLocalVariable Find(CilLocalVariable local)
        {
            if (!_parent.TryGetValue(local, out var parent))
            {
                _parent[local] = local;
                return local;
            }
            if (ReferenceEquals(parent, local))
                return local;
            var root = Find(parent);
            _parent[local] = root;
            return root;
        }

        public CilLocalVariable Union(CilLocalVariable a, CilLocalVariable b)
        {
            var rootA = Find(a);
            var rootB = Find(b);
            if (ReferenceEquals(rootA, rootB))
                return rootA;
            _parent[rootB] = rootA;
            return rootA;
        }
    }
}
