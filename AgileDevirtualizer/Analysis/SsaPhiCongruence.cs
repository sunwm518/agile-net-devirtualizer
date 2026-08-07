using AgileDevirtualizer.Decode;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Analysis;

internal sealed record SsaPhiCongruenceResult(
    bool Valid,
    string Reason,
    IReadOnlyList<SsaPhiClass> Classes,
    IReadOnlyDictionary<int, int> ValueClass,
    IReadOnlyList<SsaPhi> NeededPhis)
{
    public static SsaPhiCongruenceResult Invalid(string reason) =>
        new(false, reason, [], new Dictionary<int, int>(), []);
}

/// <summary>
/// Builds phi congruence classes. A class is closed under the phi result/input relation, so a single
/// storage slot per class reproduces phi semantics exactly: the slot always holds the definition that
/// actually reached the join. Constant-folded inputs are excluded from membership because they are
/// materialized by an explicit store instead.
/// </summary>
internal static class SsaPhiCongruence
{
    public static SsaPhiCongruenceResult Build(
        DeadCodeResult deadCode,
        SsaCilTypeResult types,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        IReadOnlySet<int> executableBlockIds)
    {
        var graph = deadCode.Sccp.Graph;
        var needed = graph.Blocks
            .Where(block => executableBlockIds.Contains(block.Id))
            .SelectMany(block => block.Phis)
            .Where(phi => deadCode.LiveValueIds.Contains(phi.Result.Id)
                && !deadCode.ConstantReplacements.ContainsKey(phi.Result.Id))
            .ToArray();
        if (needed.Length == 0)
            return new SsaPhiCongruenceResult(true, "no needed phi", [],
                new Dictionary<int, int>(), needed);

        var union = new DisjointSet();
        foreach (var phi in needed)
        {
            union.Add(phi.Result.Id);
            foreach (var input in ExecutableInputs(phi, deadCode.Sccp))
            {
                if (deadCode.ConstantReplacements.ContainsKey(input.ValueId))
                    continue;
                union.Add(input.ValueId);
                union.Union(phi.Result.Id, input.ValueId);
            }
        }

        var grouped = union.Groups()
            .Select(group => (Key: group.Min(), Members: group))
            .OrderBy(entry => entry.Key)
            .ToArray();
        var classes = new List<SsaPhiClass>(grouped.Length);
        var valueClass = new Dictionary<int, int>();
        for (int index = 0; index < grouped.Length; index++)
        {
            var members = grouped[index].Members;
            var joined = SsaCilType.Undefined;
            foreach (int member in members.Order())
                joined = SsaCilType.Join(joined, types.Values[member]);
            if (joined is not { Kind: SsaCilTypeKind.Exact, Type: { } type })
                return SsaPhiCongruenceResult.Invalid(
                    $"phi class [{string.Join(",", members.Order().Select(id => $"%{id}"))}] "
                    + $"has no exact CIL type ({joined})");
            bool needsStore = members.Any(member =>
                    graph.Value(member).Kind == SsaValueKind.Operation)
                || needed.Where(phi => members.Contains(phi.Result.Id))
                    .SelectMany(phi => ExecutableInputs(phi, deadCode.Sccp))
                    .Any(input => deadCode.ConstantReplacements.ContainsKey(input.ValueId));
            if (!TryReuseVariable(graph, members, type, decoded, tempLocalTypes, needsStore,
                out var reused, out string? reuseError))
                return SsaPhiCongruenceResult.Invalid(reuseError!);

            classes.Add(new SsaPhiClass(index, type, members, reused));
            foreach (int member in members)
                valueClass[member] = index;
        }

        return new SsaPhiCongruenceResult(true, "valid", classes, valueClass, needed);
    }

    public static IEnumerable<SsaPhiInput> ExecutableInputs(SsaPhi phi, SccpResult sccp) =>
        phi.Inputs.Where(input => input.Kind == SsaPhiInputKind.MethodEntry
            || sccp.ExecutableEdges.Any(edge =>
                edge.SourceBlockId == input.PredecessorBlockId
                && edge.TargetBlockId == phi.Result.DefinitionBlockId));

    /// <summary>
    /// A class seeded by exactly one initial variable can live in that slot itself, which removes the
    /// entry copy entirely. A class that never receives a store is a pure pass-through, so even an
    /// argument slot can host it. A class that does receive stores may only reuse a local, and only
    /// when the declared slot type is exactly the class type; no other writer of that local survives
    /// dead-store elimination, so the slot has a single owner either way.
    /// </summary>
    private static bool TryReuseVariable(
        SsaGraph graph,
        IReadOnlySet<int> members,
        TypeSignature type,
        DecodedMethod decoded,
        IReadOnlyList<TypeSignature> tempLocalTypes,
        bool needsStore,
        out SsaVariableSlot? reused,
        out string? error)
    {
        reused = null;
        error = null;
        var initial = members
            .Select(graph.Value)
            .Where(value => value.Kind is SsaValueKind.InitialLocal
                or SsaValueKind.InitialArgument)
            .ToArray();
        if (initial.Length == 0)
            return true;
        if (initial.Length > 1)
        {
            error = "phi class merges more than one initial variable: "
                + string.Join(", ", initial.Select(value => $"%{value.Id}"));
            return false;
        }
        if (initial[0].Variable is not { } variable)
            return true;
        if (variable.Kind == SsaVariableKind.Argument)
        {
            if (!needsStore)
                reused = variable;
            return true;
        }
        var declared = variable.Temporary ? tempLocalTypes : decoded.Locals;
        if (variable.Index < 0 || variable.Index >= declared.Count)
        {
            error = $"initial local {variable} is outside the declared local set";
            return false;
        }
        if (!needsStore || declared[variable.Index].FullName == type.FullName)
            reused = variable;
        return true;
    }

    private sealed class DisjointSet
    {
        private readonly Dictionary<int, int> _parent = [];

        public void Add(int item) => _parent.TryAdd(item, item);

        public int Find(int item)
        {
            int root = item;
            while (_parent[root] != root)
                root = _parent[root];
            while (_parent[item] != root)
                (item, _parent[item]) = (_parent[item], root);
            return root;
        }

        public void Union(int left, int right)
        {
            int leftRoot = Find(left);
            int rightRoot = Find(right);
            if (leftRoot == rightRoot)
                return;
            if (rightRoot < leftRoot)
                (leftRoot, rightRoot) = (rightRoot, leftRoot);
            _parent[rightRoot] = leftRoot;
        }

        public IEnumerable<IReadOnlySet<int>> Groups() => _parent.Keys
            .GroupBy(Find)
            .Select(group => (IReadOnlySet<int>)group.ToHashSet());
    }
}
