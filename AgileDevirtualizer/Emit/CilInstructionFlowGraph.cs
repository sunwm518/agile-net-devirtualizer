using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Shared raw-CIL flow graph construction: real branch/fallthrough successors, optionally widened
/// with two conservative edge families that no real branch instruction encodes. (1) An exceptional
/// edge from every instruction inside a try region to its handler's entry (the filter's entry when the
/// clause has one) — an exception can occur at essentially any instruction in the region, so a value
/// the handler could read must stay reachable from there. (2) A `leave` that exits one or more
/// `finally`/`fault`-protected regions implicitly runs each exited region's handler before actually
/// reaching its stated target — CIL never encodes that as a branch, but a value that must survive
/// across the `leave` needs to be seen as live through the finally's own body too, or a later pass
/// could wrongly conclude the finally's locals never coexist with it and merge them.
/// </summary>
internal static class CilInstructionFlowGraph
{
    public static Dictionary<CilInstruction, int> IndexInstructions(CilMethodBody body)
    {
        var indexOf = new Dictionary<CilInstruction, int>();
        for (int index = 0; index < body.Instructions.Count; index++)
            indexOf.TryAdd(body.Instructions[index], index);
        return indexOf;
    }

    public static Dictionary<int, List<int>> BuildSuccessors(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf,
        bool includeExceptionEdges)
    {
        var successors = new Dictionary<int, List<int>>();
        for (int position = 0; position < body.Instructions.Count; position++)
            successors[position] = RawSuccessors(body.Instructions, indexOf, position).ToList();
        if (includeExceptionEdges)
        {
            AddExceptionDispatchEdges(body, indexOf, successors);
            AddFinallyChainEdges(body, indexOf, successors);
        }
        return successors;
    }

    private static void AddExceptionDispatchEdges(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf,
        Dictionary<int, List<int>> successors)
    {
        foreach (var handler in body.ExceptionHandlers)
        {
            if (!TryResolve(handler.TryStart, indexOf, out int tryStart)
                || !TryResolve(handler.TryEnd, indexOf, out int tryEnd))
                continue;
            int? entry = handler.FilterStart is { } filterStart
                && TryResolve(filterStart, indexOf, out int filterIndex) ? filterIndex
                : TryResolve(handler.HandlerStart, indexOf, out int handlerIndex) ? handlerIndex
                : null;
            if (entry is not { } handlerEntry)
                continue;
            for (int position = tryStart; position < tryEnd && position < body.Instructions.Count;
                position++)
                successors[position].Add(handlerEntry);
        }
    }

    /// <summary>
    /// For every `leave`, finds the finally/fault clauses it exits (present at the leave's own
    /// position, absent at its stated target) and orders them innermost-first by protected-extent
    /// size. Wires the leave to the innermost handler's entry, each handler's `endfinally` positions to
    /// the next handler's entry, and the outermost handler's `endfinally` positions to the leave's
    /// original stated target — modeling the real, CIL-implicit unwind chain.
    /// </summary>
    private static void AddFinallyChainEdges(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf,
        Dictionary<int, List<int>> successors)
    {
        var finallyOrFault = new List<int>();
        for (int clause = 0; clause < body.ExceptionHandlers.Count; clause++)
            if (body.ExceptionHandlers[clause].HandlerType is
                CilExceptionHandlerType.Finally or CilExceptionHandlerType.Fault)
                finallyOrFault.Add(clause);
        if (finallyOrFault.Count == 0)
            return;

        var enclosing = BuildEnclosingClauses(body, indexOf);
        var handlerEntry = new int?[body.ExceptionHandlers.Count];
        var handlerExtentSize = new int[body.ExceptionHandlers.Count];
        var endfinallyPositions = new List<int>[body.ExceptionHandlers.Count];
        foreach (int clause in finallyOrFault)
        {
            endfinallyPositions[clause] = [];
            var handler = body.ExceptionHandlers[clause];
            if (!TryResolve(handler.HandlerStart, indexOf, out int handlerStart)
                || !TryResolve(handler.HandlerEnd, indexOf, out int handlerEnd))
                continue;
            handlerEntry[clause] = handlerStart;
            handlerExtentSize[clause] = handlerEnd - handlerStart;
            for (int position = handlerStart; position < handlerEnd
                && position < body.Instructions.Count; position++)
                if (body.Instructions[position].OpCode.Code == CilCode.Endfinally)
                    endfinallyPositions[clause].Add(position);
        }

        for (int position = 0; position < body.Instructions.Count; position++)
        {
            var instruction = body.Instructions[position];
            if (instruction.OpCode.Code is not (CilCode.Leave or CilCode.Leave_S)
                || instruction.Operand is not CilInstructionLabel { Instruction: { } targetInstruction }
                || !indexOf.TryGetValue(targetInstruction, out int target))
                continue;

            var exited = finallyOrFault
                .Where(clause => handlerEntry[clause] is not null
                    && enclosing[position].Contains(clause) && !enclosing[target].Contains(clause))
                .OrderBy(clause => handlerExtentSize[clause])
                .ToArray();
            if (exited.Length == 0)
                continue;

            successors[position].Add(handlerEntry[exited[0]]!.Value);
            for (int i = 0; i < exited.Length; i++)
            {
                int nextTarget = i + 1 < exited.Length ? handlerEntry[exited[i + 1]]!.Value : target;
                foreach (int endfinally in endfinallyPositions[exited[i]])
                    successors[endfinally].Add(nextTarget);
            }
        }
    }

    /// <summary>
    /// Every position's full protected extent (try start through handler end), keyed by clause index —
    /// unlike zone-specific membership, this treats a clause's try and handler bodies as one contiguous
    /// "owned by clause C" span, which is what determines whether leaving a position also exits C.
    /// </summary>
    private static Dictionary<int, HashSet<int>> BuildEnclosingClauses(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf)
    {
        var enclosing = new Dictionary<int, HashSet<int>>();
        for (int index = 0; index < body.Instructions.Count; index++)
            enclosing[index] = [];
        for (int clause = 0; clause < body.ExceptionHandlers.Count; clause++)
        {
            var handler = body.ExceptionHandlers[clause];
            if (!TryResolve(handler.TryStart, indexOf, out int tryStart)
                || !TryResolve(handler.HandlerEnd, indexOf, out int handlerEnd))
                continue;
            int start = tryStart;
            if (handler.FilterStart is { } filterStart && TryResolve(filterStart, indexOf,
                out int filterIndex) && filterIndex < start)
                start = filterIndex;
            if (TryResolve(handler.HandlerStart, indexOf, out int handlerStart)
                && handlerStart < start)
                start = handlerStart;
            for (int position = start; position < handlerEnd && position < body.Instructions.Count;
                position++)
                enclosing[position].Add(clause);
        }
        return enclosing;
    }

    /// <summary>
    /// Every position's exception-region membership, keyed by (clause index, zone). Two positions in
    /// the identical set are governed by the same set of try/handler/filter ranges; this is a
    /// conservative structural stand-in for the semantic `RegionPath` at the raw CIL layer.
    /// </summary>
    public static Dictionary<int, HashSet<(int Clause, int Zone)>> BuildMembership(
        CilMethodBody body,
        Dictionary<CilInstruction, int> indexOf)
    {
        var membership = new Dictionary<int, HashSet<(int, int)>>();
        for (int index = 0; index < body.Instructions.Count; index++)
            membership[index] = [];
        for (int clause = 0; clause < body.ExceptionHandlers.Count; clause++)
        {
            var handler = body.ExceptionHandlers[clause];
            AddRange(handler.TryStart, handler.TryEnd, clause, 0);
            if (handler.FilterStart is { } filterStart)
                AddRange(filterStart, handler.HandlerStart, clause, 2);
            AddRange(handler.HandlerStart, handler.HandlerEnd, clause, 1);
        }
        return membership;

        void AddRange(ICilLabel? start, ICilLabel? end, int clause, int zone)
        {
            if (!TryResolve(start, indexOf, out int startIndex)
                || !TryResolve(end, indexOf, out int endIndex))
                return;
            for (int index = startIndex; index < endIndex && index < body.Instructions.Count; index++)
                membership[index].Add((clause, zone));
        }
    }

    private static bool TryResolve(
        ICilLabel? label,
        Dictionary<CilInstruction, int> indexOf,
        out int index)
    {
        if (label is CilInstructionLabel { Instruction: { } instruction }
            && indexOf.TryGetValue(instruction, out index))
            return true;
        index = -1;
        return false;
    }

    private static IEnumerable<int> RawSuccessors(
        IList<CilInstruction> instructions,
        Dictionary<CilInstruction, int> indexOf,
        int position)
    {
        var instruction = instructions[position];
        switch (instruction.OpCode.Code)
        {
            case CilCode.Ret:
            case CilCode.Throw:
            case CilCode.Rethrow:
            case CilCode.Endfinally:
            case CilCode.Endfilter:
                yield break;
        }

        bool hasFallthrough = true;
        if (instruction.Operand is CilInstructionLabel { Instruction: { } target }
            && indexOf.TryGetValue(target, out int targetIndex))
        {
            yield return targetIndex;
            hasFallthrough = instruction.OpCode.Code is not (CilCode.Br or CilCode.Br_S
                or CilCode.Leave or CilCode.Leave_S);
        }
        else if (instruction.Operand is IList<ICilLabel> table)
        {
            foreach (var label in table.OfType<CilInstructionLabel>())
                if (label.Instruction is { } tableTarget
                    && indexOf.TryGetValue(tableTarget, out int tableIndex))
                    yield return tableIndex;
        }

        if (hasFallthrough && position + 1 < instructions.Count)
            yield return position + 1;
    }
}
