namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Immutable worklist state. Stack is bottom-to-top; null denotes an unknown/conflicting shape.
/// Missing locals are the lattice top (Unknown), keeping the representation finite and sparse.
/// </summary>
internal sealed class AbstractState
{
    public AbstractState(
        bool reachable,
        IReadOnlyList<AbstractValue>? stack,
        IReadOnlyDictionary<SemanticLocalReference, AbstractValue> locals,
        RegionPath regionPath,
        bool imprecise)
    {
        Reachable = reachable;
        Stack = stack;
        Locals = locals;
        RegionPath = regionPath;
        IsImprecise = imprecise;
    }

    public bool Reachable { get; }
    public IReadOnlyList<AbstractValue>? Stack { get; }
    public IReadOnlyDictionary<SemanticLocalReference, AbstractValue> Locals { get; }
    public RegionPath RegionPath { get; }
    public bool IsImprecise { get; }

    public static AbstractState Unreachable(RegionPath regionPath) =>
        new(false, Array.Empty<AbstractValue>(),
            new Dictionary<SemanticLocalReference, AbstractValue>(), regionPath, false);

    public static AbstractState Entry(RegionPath regionPath) =>
        new(true, Array.Empty<AbstractValue>(),
            new Dictionary<SemanticLocalReference, AbstractValue>(), regionPath, false);

    public AbstractState WithRegion(RegionPath regionPath) =>
        new(Reachable, Stack, Locals, regionPath, IsImprecise);

    public static AbstractState Join(AbstractState current, AbstractState incoming, RegionPath targetPath)
    {
        if (!current.Reachable)
            return incoming.WithRegion(targetPath);
        if (!incoming.Reachable)
            return current;

        bool imprecise = current.IsImprecise || incoming.IsImprecise;
        IReadOnlyList<AbstractValue>? stack;
        if (current.Stack is null || incoming.Stack is null
            || current.Stack.Count != incoming.Stack.Count)
        {
            stack = null;
            imprecise = true;
        }
        else
        {
            var joined = new AbstractValue[current.Stack.Count];
            for (int index = 0; index < joined.Length; index++)
                joined[index] = AbstractValue.Join(current.Stack[index], incoming.Stack[index]);
            stack = joined;
        }

        var locals = new Dictionary<SemanticLocalReference, AbstractValue>();
        foreach (var slot in current.Locals.Keys.Union(incoming.Locals.Keys))
        {
            var left = current.Locals.GetValueOrDefault(slot, AbstractValue.Unknown);
            var right = incoming.Locals.GetValueOrDefault(slot, AbstractValue.Unknown);
            var value = AbstractValue.Join(left, right);
            if (value.Kind != AbstractValueKind.Unknown)
                locals[slot] = value;
        }
        return new AbstractState(true, stack, locals, targetPath, imprecise);
    }

    public bool LatticeEquals(AbstractState other)
    {
        if (Reachable != other.Reachable || IsImprecise != other.IsImprecise)
            return false;
        if ((Stack is null) != (other.Stack is null))
            return false;
        if (Stack is not null && other.Stack is not null && !Stack.SequenceEqual(other.Stack))
            return false;
        return Locals.Count == other.Locals.Count
            && Locals.All(pair => other.Locals.TryGetValue(pair.Key, out var value)
                && value == pair.Value);
    }

    public override string ToString()
    {
        string stack = Stack is null ? "<?>" : "[" + string.Join(", ", Stack) + "]";
        string locals = "{" + string.Join(", ", Locals.OrderBy(pair => pair.Key.Temporary)
            .ThenBy(pair => pair.Key.Index)
            .Select(pair => $"{(pair.Key.Temporary ? "t" : "v")}{pair.Key.Index}={pair.Value}")) + "}";
        return $"reachable={Reachable} stack={stack} locals={locals} region={RegionPath} "
            + $"imprecise={IsImprecise}";
    }
}

/// <summary>Mutable transfer helper scoped to one basic block.</summary>
internal sealed class AbstractStateBuilder
{
    private List<AbstractValue>? _stack;
    private readonly Dictionary<SemanticLocalReference, AbstractValue> _locals;
    private bool _imprecise;

    public AbstractStateBuilder(AbstractState state)
    {
        _stack = state.Stack?.ToList();
        _locals = new Dictionary<SemanticLocalReference, AbstractValue>(state.Locals);
        _imprecise = state.IsImprecise;
        RegionPath = state.RegionPath;
    }

    public RegionPath RegionPath { get; }

    public void Push(AbstractValue value) => _stack?.Add(value);

    public AbstractValue Pop()
    {
        if (_stack is null)
            return AbstractValue.Unknown;
        if (_stack.Count == 0)
        {
            _stack = null;
            _imprecise = true;
            return AbstractValue.Unknown;
        }
        var value = _stack[^1];
        _stack.RemoveAt(_stack.Count - 1);
        return value;
    }

    public AbstractValue Peek() => _stack is { Count: > 0 } ? _stack[^1] : AbstractValue.Unknown;

    public void PopIfPresent()
    {
        if (_stack is { Count: > 0 })
            _stack.RemoveAt(_stack.Count - 1);
    }

    public void StoreLocal(SemanticLocalReference slot, AbstractValue value)
    {
        if (value.Kind == AbstractValueKind.Unknown)
            _locals.Remove(slot);
        else
            _locals[slot] = value;
    }

    public AbstractValue LoadLocal(SemanticLocalReference slot) =>
        _locals.GetValueOrDefault(slot, AbstractValue.Unknown);

    public void MarkImprecise() => _imprecise = true;

    public AbstractState Snapshot() => new(true, _stack?.ToArray(),
        new Dictionary<SemanticLocalReference, AbstractValue>(_locals), RegionPath, _imprecise);
}
