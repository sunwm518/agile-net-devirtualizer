using System.Linq;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

// Local, per-branch-site resolution of a branch on a genuine VM comparison result. A fused handler
// can contain SEVERAL independent comparisons (e.g. one whose result is merely stored to a scratch
// local, and a separate, later one that drives the real VM branch) — resolving each branch on its
// own, right where it occurs, keeps them from being coupled together (which a whole-handler
// force-true/force-false two-pass would do, corrupting anything unrelated to the real branch).
//
// Two shapes are recognised, both by TRIAL execution (snapshot state, explore, restore — never
// committing until a shape matches):
//   - "Materialise as a value" (a closed C# ternary, e.g. `cond ? 1 : 0` compiled unoptimised): both
//     arms are pure (emit no real CIL) and reconverge at the same instruction, differing only in an
//     int constant of {0,1}/{1,0} — replace with the ORIGINAL comparison call (+ negate if needed)
//     and keep interpreting from the convergence point.
//   - "Open branch" (the real VM instruction boundary): both arms run straight to a terminator
//     (SetIp) with no other emitted ops, landing on two different VM-instruction targets — emit a
//     call to the original comparison + brtrue/brfalse(/br) to those targets, and stop.
// Anything else is reported as unsupported rather than guessed at.
internal sealed partial class ExecuteInterpreter
{
    private readonly record struct StateSnapshot(
        SymValue[] EvalTopToBottom, Dictionary<int, SymValue> Locals, int OutCount,
        TermKind TermKind, int TermTarget, VmTarget[]? TermSwitch, VmStackType[] VmValueTypesTopToBottom,
        Dictionary<int, TypeSignature?> VmLocalKnownTypes);

    private StateSnapshot TakeSnapshot() => new(
        _eval.ToArray(), new Dictionary<int, SymValue>(_locals), _out.Count, _termKind, _termTarget, _termSwitch,
        _vmValueTypes.ToArray(), new Dictionary<int, TypeSignature?>(_vmLocalKnownTypes));

    private void RestoreSnapshot(StateSnapshot s)
    {
        // Enumerable.Reverse(array), called by its full static form rather than dot-syntax: an
        // array is also implicitly convertible to Span<T>, and MemoryExtensions.Reverse(Span<T>) —
        // an in-place, void-returning overload — sits in the same implicitly-global System
        // namespace as the LINQ one. Which of the two extension-method candidates wins is not
        // guaranteed identical across SDK versions; calling Enumerable.Reverse directly removes the
        // ambiguity outright instead of relying on that resolution.
        _eval = new Stack<SymValue>(Enumerable.Reverse(s.EvalTopToBottom)); // Reverse+ctor round-trips the original top order.
        _locals.Clear();
        foreach (var kv in s.Locals) _locals[kv.Key] = kv.Value;
        if (_out.Count > s.OutCount)
            _out.RemoveRange(s.OutCount, _out.Count - s.OutCount);
        _termKind = s.TermKind; _termTarget = s.TermTarget; _termSwitch = s.TermSwitch;
        _vmValueTypes.Clear();
        foreach (var t in Enumerable.Reverse(s.VmValueTypesTopToBottom)) _vmValueTypes.Push(t);
        _vmLocalKnownTypes.Clear();
        foreach (var kv in s.VmLocalKnownTypes) _vmLocalKnownTypes[kv.Key] = kv.Value;
    }

    /// <summary>Tries the "closed ternary" shape: both arms are pure value-producers that reconverge.</summary>
    private bool TryMaterializeTernary(SymValue.Cond cond, int trueIp, int falseIp, out int convergeIp, out SymValue merged)
    {
        convergeIp = -1;
        merged = null!;
        var snap = TakeSnapshot();
        try
        {
            // Whichever arm sits at the LOWER instruction index is, by construction of how compilers
            // lay out `cond ? a : b`, the one with an explicit trailing `br` to the shared continuation;
            // the higher one simply falls through into it.
            int firstIp = Math.Min(trueIp, falseIp);
            int secondIp = Math.Max(trueIp, falseIp);
            bool firstIsTrue = firstIp == trueIp;

            if (!RunArmToUnconditionalBranch(firstIp, out int conv, out var firstVal, out int firstOps))
                return false;
            RestoreSnapshot(snap);

            if (!RunArmUntilIp(secondIp, conv, out var secondVal, out int secondOps))
                return false;
            RestoreSnapshot(snap);

            if (firstOps != 0 || secondOps != 0)
                return false; // a real side effect in either arm — not a pure value-select.

            var trueVal = firstIsTrue ? firstVal : secondVal;
            var falseVal = firstIsTrue ? secondVal : firstVal;
            if (trueVal is not SymValue.Operand { Value: int tv } || falseVal is not SymValue.Operand { Value: int fv })
                return false;
            if ((tv, fv) != (1, 0) && (tv, fv) != (0, 1))
                return false;

            convergeIp = conv;
            merged = (tv, fv) == (1, 0) ? cond : cond with { Negate = !cond.Negate };
            return true;
        }
        finally
        {
            RestoreSnapshot(snap);
        }
    }

    /// <summary>Tries the "open branch" shape: both arms run straight to a SetIp, no other side effects.</summary>
    private bool TryResolveOpenBranch(SymValue.Cond cond, int trueIp, int falseIp)
    {
        var snap = TakeSnapshot();
        bool trueOk = RunArmToTerminator(trueIp, out var trueTerm, out int trueOps);
        RestoreSnapshot(snap);
        bool falseOk = RunArmToTerminator(falseIp, out var falseTerm, out int falseOps);
        RestoreSnapshot(snap);

        if (Environment.GetEnvironmentVariable("TRACE_OPENBRANCH") == "1")
            Console.Error.WriteLine($"[openbranch vm={_instr.Index}/{_body.Count}] trueOk={trueOk} trueTerm=({trueTerm.Kind},{trueTerm.Target}) trueOps={trueOps} | falseOk={falseOk} falseTerm=({falseTerm.Kind},{falseTerm.Target}) falseOps={falseOps}");

        if (!trueOk || !falseOk || trueOps != 0 || falseOps != 0)
            return false;
        // Scoped to the observed shape: both arms resolve to a plain instruction-index branch.
        if (trueTerm.Kind != TermKind.Branch || falseTerm.Kind != TermKind.Branch)
            return false;
        if (trueTerm.Target == falseTerm.Target)
            return false; // condition doesn't actually affect the outcome — not expected, bail safely.

        // The comparison's Call was already emitted eagerly at production time; only the branch
        // itself (plus an outstanding negation) remains to be emitted here.
        int fall = _instr.Index + 1;
        if (cond.Negate) { Emit(CilOpCodes.Ldc_I4, 0); Emit(CilOpCodes.Ceq); }

        if (falseTerm.Target == fall)
            Emit(CilOpCodes.Brtrue, new VmTarget(trueTerm.Target));
        else if (trueTerm.Target == fall)
            Emit(CilOpCodes.Brfalse, new VmTarget(falseTerm.Target));
        else
        {
            Emit(CilOpCodes.Brtrue, new VmTarget(trueTerm.Target));
            Emit(CilOpCodes.Br, new VmTarget(falseTerm.Target));
        }
        _termKind = TermKind.Resolved;
        return true;
    }

    private readonly record struct ArmTerminator(TermKind Kind, int Target);

    /// <summary>Runs from <paramref name="startIp"/> until it executes an unconditional branch,
    /// WITHOUT taking it — reports that branch's target (the ternary's convergence point) and
    /// whatever value the arm left on top of the eval stack.</summary>
    private bool RunArmToUnconditionalBranch(int startIp, out int target, out SymValue value, out int opsEmitted)
    {
        target = -1; value = null!; opsEmitted = 0;
        int ip = startIp;
        int baseOut = _out.Count;
        var initialTerm = CapturePendingTerminator();
        try
        {
            for (int steps = 0; steps < 40; steps++)
            {
                if (ip < 0 || ip >= _body.Count) return false;
                var cil = _body[ip];
                if (cil.OpCode.Code is CilCode.Br or CilCode.Br_S)
                {
                    target = Target(cil);
                    value = _eval.Count > 0 ? _eval.Peek() : new SymValue.Unknown("ternary-empty-arm");
                    opsEmitted = _out.Count - baseOut;
                    return true;
                }
                int next = ip + 1;
                if (!Step(cil, ref next) || !PendingTerminatorEquals(initialTerm))
                    return false; // hit ret/a terminator before reaching an unconditional branch.
                ip = next;
            }
            return false;
        }
        catch
        {
            return false; // any interpretation failure just means this isn't the expected shape.
        }
    }

    /// <summary>Runs from <paramref name="startIp"/> until ip reaches <paramref name="stopIp"/>.</summary>
    private bool RunArmUntilIp(int startIp, int stopIp, out SymValue value, out int opsEmitted)
    {
        value = null!; opsEmitted = 0;
        int ip = startIp;
        int baseOut = _out.Count;
        var initialTerm = CapturePendingTerminator();
        try
        {
            for (int steps = 0; ip != stopIp; steps++)
            {
                if (steps >= 40 || ip < 0 || ip >= _body.Count) return false;
                var cil = _body[ip];
                int next = ip + 1;
                if (!Step(cil, ref next) || !PendingTerminatorEquals(initialTerm))
                    return false;
                ip = next;
            }
            value = _eval.Count > 0 ? _eval.Peek() : new SymValue.Unknown("ternary-empty-arm");
            opsEmitted = _out.Count - baseOut;
            return true;
        }
        catch
        {
            return false;
        }
    }

    // A fused handler can already have a provisional SetIp from an earlier sub-operation. A pure
    // ternary in a later sub-operation is still safe to trial as long as neither arm changes that
    // pending terminator. Requiring TermKind.None here rejected exactly this valid shape.
    private readonly record struct PendingTerminator(TermKind Kind, int Target, VmTarget[]? Switch);

    private PendingTerminator CapturePendingTerminator() =>
        new(_termKind, _termTarget, _termSwitch);

    private bool PendingTerminatorEquals(PendingTerminator initial) =>
        _termKind == initial.Kind
        && _termTarget == initial.Target
        && ReferenceEquals(_termSwitch, initial.Switch);

    /// <summary>
    /// Runs from <paramref name="startIp"/> to the END of this VM instruction's effect along this
    /// path — i.e. all the way to the handler's own <c>ret</c> (mirroring the main loop, which also
    /// keeps going through dead/intermediate SetIps and only reports whichever one executed last).
    /// A nested branch resolution that fully resolves (sets `Resolved`) also stops the run; the
    /// caller's opsEmitted check rejects that case (a Resolved branch always emits something).
    /// </summary>
    private bool RunArmToTerminator(int startIp, out ArmTerminator term, out int opsEmitted)
    {
        term = default; opsEmitted = 0;
        int ip = startIp;
        int baseOut = _out.Count;
        try
        {
            for (int steps = 0; ip >= 0 && ip < _body.Count && _termKind != TermKind.Resolved; steps++)
            {
                if (steps >= 2000) return false;
                var cil = _body[ip];
                int next = ip + 1;
                // The handler's own `ret` just ends its C# method — it does NOT mean "no SetIp
                // happened"; report whatever `_termKind`/`_termTarget` a PRIOR SetIp already set
                // (mirroring EmitTerminator), the same as reaching the end of the IL does below.
                if (!Step(cil, ref next))
                    break;
                ip = next;
            }
            term = _termKind == TermKind.Branch ? new ArmTerminator(TermKind.Branch, _termTarget)
                 : new ArmTerminator(_termKind, -1);
            opsEmitted = _out.Count - baseOut;
            return true;
        }
        catch (Exception ex)
        {
            if (Environment.GetEnvironmentVariable("TRACE_OPENBRANCH") == "1")
                Console.Error.WriteLine($"[openbranch vm={_instr.Index}/{_body.Count}] RunArmToTerminator({startIp}) threw: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }
}
