using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

// Arithmetic / comparison / conversion on the execute method's OWN IL. These are always VM
// bookkeeping (index math, IP math, guard comparisons): the program's real arithmetic and
// comparisons go through the VM helper methods (JH4=/bH4=), recognised elsewhere and emitted when
// their result is pushed. So here we only fold constants / IP offsets / jump tables and never emit.
internal sealed partial class ExecuteInterpreter
{
    // A Cond is also a genuine, already-emitted real-stack value (a runtime-determined bool) — see
    // SymValue.Cond — so it counts as "on the real stack" wherever OnStack does.
    private static bool IsStack(SymValue v) => v is SymValue.OnStack or SymValue.Cond;

    /// <summary>
    /// Balances an operand this bookkeeping arithmetic/comparison is about to abandon (it didn't
    /// fold into anything). Safe ONLY when the value was never stored to any handler-own local
    /// (<see cref="_storedToLocal"/>) — a value that WAS stored might still be read again much later
    /// from that local (e.g. an `obj == null` guard, with `obj` reused ~20 instructions later as an
    /// Invoke receiver); discarding it here would silently corrupt that later use. A value that was
    /// NEVER stored anywhere is a purely transient, single-use expression result (e.g. `IntPtr.Size`
    /// used inline in a ternary condition) with no other possible reader, so it's genuinely dead —
    /// exactly like the C# compiler's own real `pop` instruction (see the CilCode.Pop case), which
    /// only ever exists when a value truly has no consumer.
    /// </summary>
    private void DiscardIfTransient(params SymValue[] values)
    {
        foreach (var v in values)
            if (IsStack(v) && !_storedToLocal.Contains(v)) Emit(CilOpCodes.Pop);
    }

    private void Binary(CilOpCode emit, Func<long, long, long>? fold, bool ipCapable = false)
    {
        _ = emit;
        var b = Pop();
        var a = Pop();
        if (a is SymValue.SwitchTable sta) { _eval.Push(CombineSwitch(sta, b)); return; }
        if (b is SymValue.SwitchTable stb) { _eval.Push(CombineSwitch(stb, a)); return; }
        if (ipCapable && fold is not null)
        {
            if (a is SymValue.Ip ip && TryInt(b, out int kb)) { _eval.Push(new SymValue.Ip((int)fold(ip.Offset, kb))); return; }
            if (b is SymValue.Ip ip2 && TryInt(a, out int ka)) { _eval.Push(new SymValue.Ip((int)fold(ka, ip2.Offset))); return; }
        }
        if (fold is not null && TryLong(a, out long la) && TryLong(b, out long lb)) { _eval.Push(new SymValue.Operand((int)fold(la, lb))); return; }
        DiscardIfTransient(b, a);
        _eval.Push(new SymValue.Unknown("bookkeeping-arith"));
    }

    private void Compare(CilOpCode emit, Func<long, long, bool>? fold)
    {
        var b = Pop();
        var a = Pop();
        if (fold is not null && TryLong(a, out long la) && TryLong(b, out long lb)) { _eval.Push(new SymValue.Operand(fold(la, lb) ? 1 : 0)); return; }
        // cgt.un/clt.un against a literal null is the standard compiled form of a reference `!= null`
        // / `== null` check (the verifier permits unsigned ordering compares against null for
        // reference types) — resolve it via the same truthiness test a direct branch would use,
        // instead of always discarding it as unknowable bookkeeping.
        if (fold is null && TryNullCheck(emit.Code, a, b, out bool nullCheck))
        {
            // The non-null side may be a genuine value already sitting on the real CIL stack (e.g.
            // the runtime's own "is this boxed value an X?" isinst result) — the null-check consumed
            // it symbolically, but the real stack slot still needs balancing, same as any other
            // bookkeeping fold that abandons its operands.
            DiscardIfTransient(b, a);
            _eval.Push(new SymValue.Operand(nullCheck ? 1 : 0));
            return;
        }
        DiscardIfTransient(b, a);
        _eval.Push(new SymValue.Unknown("bookkeeping-compare"));
    }

    private static bool TryNullCheck(CilCode code, SymValue a, SymValue b, out bool result)
    {
        bool aNull = IsNullLiteral(a);
        bool bNull = IsNullLiteral(b);
        if (code == CilCode.Cgt_Un)
        {
            if (bNull && TryConstBool(a, out bool av)) { result = av; return true; } // a >u 0  <=>  a != null
            if (aNull) { result = false; return true; }                              // 0 >u b never holds
        }
        else if (code == CilCode.Clt_Un)
        {
            if (aNull && TryConstBool(b, out bool bv)) { result = bv; return true; } // 0 <u b  <=>  b != null
            if (bNull) { result = false; return true; }                              // a <u 0 never holds
        }
        result = false;
        return false;
    }

    /// <summary>
    /// `ceq` on the execute method's OWN IL, generalised beyond plain integers: also resolves
    /// reference/null and <c>Type</c> equality (via <see cref="TryConstEq"/>) — needed for the
    /// runtime's <c>value.GetType() == typeof(X)</c> numeric-conversion dispatch, resolved concretely
    /// once <see cref="KnownTypeOf"/> has tracked the value's type through the VM eval-stack shadow.
    /// </summary>
    private void CompareEqGeneral()
    {
        var b = Pop();
        var a = Pop();
        // `ceq` against a Cond is the standard C# compiler idiom for `!boolExpr` (compare to 0) or
        // the identity `boolExpr` (compare to 1) — preserve the Cond (toggling Negate) instead of
        // collapsing it to opaque bookkeeping, so a later branch/ternary can still resolve it.
        if (a is SymValue.Cond ac && TryInt(b, out int bi) && bi is 0 or 1)
        { _eval.Push(ac with { Negate = ac.Negate ^ (bi == 0) }); return; }
        if (b is SymValue.Cond bc && TryInt(a, out int ai) && ai is 0 or 1)
        { _eval.Push(bc with { Negate = bc.Negate ^ (ai == 0) }); return; }
        if (a is SymValue.Unknown || b is SymValue.Unknown) { DiscardIfTransient(b, a); _eval.Push(new SymValue.Unknown("bookkeeping-compare")); return; }
        if (TryConstEq(a, b, out bool eq)) { _eval.Push(new SymValue.Operand(eq ? 1 : 0)); return; }
        DiscardIfTransient(b, a);
        _eval.Push(new SymValue.Unknown("bookkeeping-compare"));
    }

    private void Unary(CilOpCode emit)
    {
        _ = emit;
        DiscardIfTransient(Pop());
        _eval.Push(new SymValue.Unknown("bookkeeping-unary"));
    }

    private void Conv(CilOpCode emit)
    {
        _ = emit;
        _eval.Push(Pop()); // a raw conversion of a bookkeeping value: keep it unchanged
    }

    private SymValue CombineSwitch(SymValue.SwitchTable t, SymValue other)
    {
        if (other is SymValue.Ip ip) return new SymValue.SwitchTable(t.Deltas, t.Base + ip.Offset);
        if (TryInt(other, out int k)) return new SymValue.SwitchTable(t.Deltas, t.Base + k);
        DiscardIfTransient(other);
        return t;
    }

    private static bool TryLong(SymValue v, out long result)
    {
        if (v is SymValue.Operand { Value: { } o } && IsIntLike(o)) { result = Convert.ToInt64(o); return true; }
        result = 0;
        return false;
    }
}
