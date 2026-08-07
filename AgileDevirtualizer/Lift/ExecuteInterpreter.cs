using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Lifts one VM instruction to a CIL sequence by symbolically interpreting its handler's
/// execute-method IL. The VM eval stack IS the reconstructed CIL eval stack: whenever the handler
/// pushes a source value (local/arg/constant) we emit the matching load; whenever it performs a
/// consuming operation (store/call/newobj/field/branch/return) we emit that. Control flow inside
/// the handler branches on <em>reflection facts of the resolved operand member</em> (IsStatic,
/// void return, …), which we evaluate concretely, so each VM instruction lifts for its real token.
/// Branches on a genuine VM comparison result (a <see cref="SymValue.Cond"/>) are resolved locally,
/// per branch site — see <c>ExecuteInterpreter.CondBranch.cs</c> — rather than by a whole-handler
/// two-pass, so multiple independent comparisons in one fused block resolve correctly and
/// independently instead of being coupled together.
/// </summary>
internal sealed partial class ExecuteInterpreter
{
    private readonly ModuleDefinition _module;
    private readonly RuntimeVocabulary _vocab;
    private readonly RuntimeHelpers _helpers;
    private readonly ConditionClassifier _conditions;
    private readonly RuntimeContext? _ctx;

    public ExecuteInterpreter(ModuleDefinition module, RuntimeVocabulary vocab, RuntimeHelpers helpers,
                              ConditionClassifier conditions)
    {
        _module = module;
        _vocab = vocab;
        _helpers = helpers;
        _conditions = conditions;
        _ctx = module.RuntimeContext;
    }

    // Per-instruction mutable state (also snapshotted/restored by the branch resolver for trial runs).
    private VmInstruction _instr = null!;
    private List<LiftedOp> _out = null!;
    private Stack<SymValue> _eval = null!;   // the execute method's own IL operand stack
    private bool _returnOnStack;              // a value has been designated as the return value
    private CilInstructionCollection _body = null!;
    private Dictionary<int, int> _offsetToIndex = null!;
    private readonly Dictionary<int, SymValue> _locals = new();
    // Tracks (by reference, not value — two structurally-identical SymValues can be logically
    // distinct, e.g. two separate real field reads that both happen to be OnStack{TextBox}) every
    // value ever assigned to a handler-own local via Stloc. A real `pop` instruction is always safe
    // to balance with a real CIL `pop` (the C# compiler only emits `pop` when a value truly has no
    // consumer — see the CilCode.Pop case). But when OUR OWN bookkeeping arithmetic/comparison logic
    // (Arith.cs) abandons an operand because it didn't fold, that operand might still be reachable
    // via a handler local it was stored to earlier and read again much later (e.g. an `obj == null`
    // guard followed by `obj` reused as an Invoke receiver) — discarding it there would be wrong.
    // Only a value that was NEVER stored anywhere (a purely transient, single-use expression result,
    // e.g. `IntPtr.Size` used inline in a ternary condition) is safe for Arith.cs to discard.
    private readonly HashSet<SymValue> _storedToLocal = new(ReferenceEqualityComparer.Instance);

    private void StoreLocal(int index)
    {
        var value = Pop();
        _locals[index] = value;
        _storedToLocal.Add(value);
    }

    // Per-METHOD state (persists across every VM instruction's Lift() call for one method, reset by
    // BeginMethod — mirrors the VM's own eval stack/locals/args persisting across VM instructions).
    // `_vmValueTypes` shadows the REAL VM eval stack with known CLR types (or null = unknown) so a
    // handler's `value.GetType() == typeof(X)` dispatch (used to pick a numeric-conversion overload)
    // can be resolved concretely instead of guessed.
    private IReadOnlyList<TypeSignature> _vmLocalTypes = [];
    private IReadOnlyList<TypeSignature> _vmArgTypes = [];
    private IReadOnlyList<EhClause> _vmExceptionHandlers = [];
    private readonly record struct VmStackType(TypeSignature? Type, bool ManagedPointer, bool KnownNull);
    private readonly Stack<VmStackType> _vmValueTypes = new();

    // VM locals are declared generically (typically all `object`) in the bytecode's own locals
    // table — the DECLARED type tells us nothing about what's actually stored. So we ALSO track,
    // per slot index, the type of whatever was last written via SetLocal (dynamic, updated as the
    // method's VM instructions run) and prefer that over the declared type when both are available.
    private readonly Dictionary<int, TypeSignature?> _vmLocalKnownTypes = new();

    // Extra CIL locals this method's lift needs beyond the VM's own declared locals — currently only
    // for reordering-around-`box` (see EmitArgsBoxed): `box` only ever touches the top of the real
    // stack, so boxing an earlier (already-buried) call argument requires stashing later ones in a
    // scratch local while we dig down to it. Allocated on demand per Lift() call, read once by
    // CilBuilder after all of a method's instructions have been lifted.
    private readonly List<TypeSignature> _tempLocals = new();
    public IReadOnlyList<TypeSignature> TempLocalTypes => _tempLocals;

    internal string DescribeDiagnosticState()
    {
        string stack = _vmValueTypes.Count == 0
            ? "[]"
            : "[" + string.Join(", ", _vmValueTypes.Select(FormatStackType)) + "]";
        string locals = _vmLocalKnownTypes.Count == 0
            ? "{}"
            : "{" + string.Join(", ", _vmLocalKnownTypes.OrderBy(x => x.Key)
                .Select(x => $"{x.Key}:{x.Value}")) + "}";
        string handlerLocals = _locals.Count == 0
            ? "{}"
            : "{" + string.Join(", ", _locals.OrderBy(x => x.Key)
                .Select(x => $"{x.Key}:{x.Value}")) + "}";
        return $"VmStack(top-first)={stack} KnownVmLocals={locals} HandlerLocals={handlerLocals}";
    }

    private static string FormatStackType(VmStackType value)
    {
        string flags = (value.ManagedPointer ? "&" : "") + (value.KnownNull ? " null" : "");
        return (value.Type?.ToString() ?? "?") + flags;
    }

    /// <summary>
    /// Call once per devirtualized method, before lifting its first instruction. Runs a throwaway
    /// priming pass over every instruction first, solely to populate <see cref="_vmLocalKnownTypes"/>
    /// with every type ever written to each VM local across the WHOLE method: a state-machine-style
    /// method (switch-based dispatch, e.g. a coroutine-like retry loop) can READ a local, in
    /// bytecode index order, before the instruction that ESTABLISHES its type is reached in that
    /// same index order — even though the runtime's actual control flow always writes it first (the
    /// "construct" state has a higher instruction index than a later state that reads the result).
    /// A VM local holds one consistent CLR type for its whole lifetime (it's a single slot in the
    /// original, pre-virtualization method), so gathering every write up front and reusing it for
    /// the real pass is sound, not a guess. Priming failures (an instruction that doesn't lift at
    /// all, e.g. a still-unsupported idiom) are swallowed — priming only cares about type side
    /// effects, never the resulting CIL, which is discarded; the real pass re-lifts everything.
    /// </summary>
    public void BeginMethod(RuntimeModel runtime, IReadOnlyList<VmInstruction> instructions,
                            IReadOnlyList<TypeSignature> vmLocalTypes, IReadOnlyList<TypeSignature> vmArgTypes,
                            IReadOnlyList<EhClause> vmExceptionHandlers)
    {
        _vmLocalTypes = vmLocalTypes;
        _vmArgTypes = vmArgTypes;
        _vmExceptionHandlers = vmExceptionHandlers;
        _vmValueTypes.Clear();
        _vmLocalKnownTypes.Clear();
        _tempLocals.Clear();

        foreach (var instr in instructions)
            try { Lift(runtime[instr.Opcode], instr); } catch { /* type side effects only; CIL discarded */ }

        _vmValueTypes.Clear();
        _tempLocals.Clear();
    }

    /// <summary>Reserves a fresh scratch CIL local of the given type, returning its temp index.</summary>
    private int AllocTemp(TypeSignature type)
    {
        _tempLocals.Add(type);
        return _tempLocals.Count - 1;
    }

    // The handler's pending terminator. SetIp updates it (overwriting earlier ones — intermediate
    // SetIps in a fused block are dead); it is translated into a LiftedOp once, when the handler
    // returns. `Resolved` means a branch resolution already appended everything needed to `_out`.
    private enum TermKind { None, Branch, Return, Switch, Resolved }
    private TermKind _termKind;
    private int _termTarget;
    private VmTarget[]? _termSwitch;

    public List<LiftedOp> Lift(HandlerInfo handler, VmInstruction instr)
    {
        if (handler.ExecuteMethod?.CilMethodBody is not { } body)
            throw new LiftUnsupported($"handler {handler.Type.Name} has no execute body");
        return Run(handler, body, instr);
    }

    private List<LiftedOp> Run(HandlerInfo handler, CilMethodBody body, VmInstruction instr)
    {
        _instr = instr;
        _currentHandler = handler;
        _out = [];
        _eval = new Stack<SymValue>();
        _returnOnStack = false;
        _termKind = TermKind.None;
        _termSwitch = null;
        _locals.Clear();
        _storedToLocal.Clear();

        PrepareExceptionHandlerEntry();

        _body = body.Instructions;
        _body.CalculateOffsets();
        _offsetToIndex = new Dictionary<int, int>();
        for (int i = 0; i < _body.Count; i++)
            _offsetToIndex[(int)_body[i].Offset] = i;

        bool trace = Environment.GetEnvironmentVariable("TRACE_OP") == _instr.Opcode.ToString();
        if (trace)
            Console.Error.WriteLine($"[trace-op {_instr.Opcode} vm={_instr.Index} handler={body.Owner?.DeclaringType?.FullName} exec=0x{body.Owner?.MetadataToken.ToInt32():X8}] begin vmStackCount={_vmValueTypes.Count} top={string.Join(",", _vmValueTypes.Take(4))}");
        int ip = 0, guard = 0;
        // A fused handler can bundle several pseudo-ops, each seemingly ending with its own SetIp —
        // only the LAST one executed before the handler's own `ret` is real; earlier ones are dead
        // and get overwritten (see EmitTerminator, which fires once at the end using whatever
        // `_termKind` ends up being). So keep looping through ordinary terminator changes; only a
        // `Resolved` branch (which has already appended everything through the method's true end)
        // stops the loop early.
        while (ip >= 0 && ip < _body.Count && _termKind != TermKind.Resolved)
        {
            if (guard++ > 100_000)
                throw new LiftUnsupported("execute did not terminate");
            var cil = _body[ip];
            int next = ip + 1;
            if (trace) Console.Error.WriteLine($"  {ip:D3} {cil.OpCode.Mnemonic} {cil.Operand} | eval={(_eval.Count > 0 ? _eval.Peek() : null)} term={_termKind}");
            if (!Step(cil, ref next))
                break; // ret reached
            ip = next;
        }
        EmitTerminator();
        return _out;
    }

    /// <summary>Emits the handler's single terminator. A `Resolved` branch has already emitted
    /// everything it needs; a plain fall-through (target = the very next VM instruction) needs no
    /// explicit branch since the emitter lays VM instructions out in order.</summary>
    private void EmitTerminator()
    {
        switch (_termKind)
        {
            case TermKind.Return:
                Emit(CilOpCodes.Ret);
                break;
            case TermKind.Switch when _termSwitch is not null:
                Emit(CilOpCodes.Switch, _termSwitch);
                break;
            case TermKind.Branch:
                if (_termTarget != _instr.Index + 1)
                    Emit(CilOpCodes.Br, new VmTarget(_termTarget));
                break;
        }
    }

    /// <summary>Interprets one execute-IL instruction. Returns false when the handler returns.</summary>
    private bool Step(CilInstruction cil, ref int next)
    {
        switch (cil.OpCode.Code)
        {
            case CilCode.Nop:
                break;

            // The execute method's own arguments: arg0 = handler `this`, arg1 = ctx.
            case CilCode.Ldarg_0: _eval.Push(new SymValue.Unknown("handler-this")); break;      // handler instance (fields read via ldfld)
            case CilCode.Ldarg_1: _eval.Push(new SymValue.Ctx()); break;
            case CilCode.Ldarg:
            case CilCode.Ldarg_S:
                _eval.Push(ArgIndex(cil) == 1 ? new SymValue.Ctx() : new SymValue.Unknown("arg2+"));
                break;

            case CilCode.Ldfld: PushHandlerField(cil); break;

            case CilCode.Ldnull: _eval.Push(new SymValue.Constant(null)); break;
            case CilCode.Ldc_I4_M1: _eval.Push(Int(-1)); break;
            case CilCode.Ldc_I4_0: _eval.Push(Int(0)); break;
            case CilCode.Ldc_I4_1: _eval.Push(Int(1)); break;
            case CilCode.Ldc_I4_2: _eval.Push(Int(2)); break;
            case CilCode.Ldc_I4_3: _eval.Push(Int(3)); break;
            case CilCode.Ldc_I4_4: _eval.Push(Int(4)); break;
            case CilCode.Ldc_I4_5: _eval.Push(Int(5)); break;
            case CilCode.Ldc_I4_6: _eval.Push(Int(6)); break;
            case CilCode.Ldc_I4_7: _eval.Push(Int(7)); break;
            case CilCode.Ldc_I4_8: _eval.Push(Int(8)); break;
            case CilCode.Ldc_I4:
            case CilCode.Ldc_I4_S: _eval.Push(Int(Convert.ToInt32(cil.Operand))); break;
            case CilCode.Ldc_I8: _eval.Push(new SymValue.Operand(Convert.ToInt64(cil.Operand))); break;
            case CilCode.Ldc_R4: _eval.Push(new SymValue.Operand(Convert.ToSingle(cil.Operand))); break;
            case CilCode.Ldc_R8: _eval.Push(new SymValue.Operand(Convert.ToDouble(cil.Operand))); break;
            case CilCode.Ldstr: _eval.Push(new SymValue.Operand((string?)cil.Operand)); break;

            case CilCode.Ldtoken: _eval.Push(new SymValue.Operand(cil.Operand)); break; // e.g. typeof(void)

            case CilCode.Dup: _eval.Push(_eval.Count > 0 ? _eval.Peek() : new SymValue.Unknown()); break;
            // Discarding a real stack value (an unused call result) is a CIL `pop`; discarding VM
            // bookkeeping (ctx/stack refs) emits nothing.
            case CilCode.Pop: if (IsStack(Pop())) Emit(CilOpCodes.Pop); break;

            case CilCode.Ldloc_0: _eval.Push(Local(0)); break;
            case CilCode.Ldloc_1: _eval.Push(Local(1)); break;
            case CilCode.Ldloc_2: _eval.Push(Local(2)); break;
            case CilCode.Ldloc_3: _eval.Push(Local(3)); break;
            case CilCode.Ldloc:
            case CilCode.Ldloc_S: _eval.Push(Local(LocalIndex(cil))); break;
            case CilCode.Stloc_0: StoreLocal(0); break;
            case CilCode.Stloc_1: StoreLocal(1); break;
            case CilCode.Stloc_2: StoreLocal(2); break;
            case CilCode.Stloc_3: StoreLocal(3); break;
            case CilCode.Stloc:
            case CilCode.Stloc_S: StoreLocal(LocalIndex(cil)); break;

            // Preserve both the handler-local index and its current value. Most address consumers
            // remain read-only; ref-based runtime coercion helpers additionally update the local.
            case CilCode.Ldloca:
            case CilCode.Ldloca_S:
            {
                int index = LocalIndex(cil);
                _eval.Push(new SymValue.HandlerLocalAddr(index, Local(index)));
                break;
            }

            // Indexing an array: the ctx locals/args arrays yield a slot read; an operand array
            // (a handler field holding decoded values) yields the element value.
            case CilCode.Ldelem:
            case CilCode.Ldelem_Ref:
            case CilCode.Ldelem_I4:
            case CilCode.Ldelem_U2:
            case CilCode.Ldelem_I:
            case CilCode.Ldelem_I1:
            case CilCode.Ldelem_U1:
            case CilCode.Ldelem_I2:
            case CilCode.Ldelem_U4:
            case CilCode.Ldelem_I8:
            {
                var idx = Pop();
                var arr = Pop();
                if (arr is SymValue.SlotArray sa && TryInt(idx, out int si))
                    _eval.Push(new SymValue.SlotRead(sa.IsArgs, si));
                else if (arr is SymValue.Operand { Value: object?[] a } && TryInt(idx, out int ci) && ci >= 0 && ci < a.Length)
                    _eval.Push(a[ci] is DecodedStringLiteral decoded
                        ? new SymValue.ResolvedString(decoded.Value, decoded.RawToken)
                        : new SymValue.Operand(a[ci]));
                else if (arr is SymValue.Operand { Value: object?[] tbl } && IsStack(idx))
                    // an operand jump table indexed by a stack value → a switch
                    _eval.Push(new SymValue.SwitchTable([.. tbl.Select(v => Convert.ToInt32(v))], 0));
                else
                    _eval.Push(new SymValue.Unknown("ldelem-other"));
                break;
            }
            case CilCode.Ldlen: Pop(); _eval.Push(new SymValue.Unknown("ldlen")); break;

            // Boxing / unboxing on modelled values are transparent (identity preserved): box and
            // unbox.any always produce a value of EXACTLY the operand type, so the operand refines
            // the known type outright.
            case CilCode.Box:
            case CilCode.Unbox_Any:
            {
                var v = Pop();
                _eval.Push(v is SymValue.OnStack && CastTargetType(cil) is { } ct ? new SymValue.OnStack(ct) : v);
                break;
            }
            // castclass only VERIFIES compatibility with a (possibly less specific) static type — it
            // does not change the underlying object's real type, so a more specific KnownType we
            // already tracked (e.g. Char[] narrowed down from a plain Array cast) must survive; the
            // cast target is only a fallback when we don't have one yet. "System.Object" counts as
            // "no better than unknown" here too — it's the generic passthrough default from e.g. the
            // value-wrapper's Object-returning accessor, never a genuinely tracked specific type, so
            // it must not block a later, more useful narrowing (e.g. down to the real array type).
            case CilCode.Castclass:
            {
                var v = Pop();
                bool noUsefulType = v is SymValue.OnStack os && (os.KnownType is null || os.KnownType.IsTypeOf("System", "Object"));
                _eval.Push(noUsefulType && CastTargetType(cil) is { } ct ? new SymValue.OnStack(ct) : v);
                break;
            }
            case CilCode.Unbox:
                break; // produces a managed pointer; not useful for our type tracking

            // Conversions emit for real stack values, fold-through for handler constants.
            case CilCode.Conv_I: Conv(CilOpCodes.Conv_I); break;
            case CilCode.Conv_I1: Conv(CilOpCodes.Conv_I1); break;
            case CilCode.Conv_I2: Conv(CilOpCodes.Conv_I2); break;
            case CilCode.Conv_I4: Conv(CilOpCodes.Conv_I4); break;
            case CilCode.Conv_I8: Conv(CilOpCodes.Conv_I8); break;
            case CilCode.Conv_U: Conv(CilOpCodes.Conv_U); break;
            case CilCode.Conv_U1: Conv(CilOpCodes.Conv_U1); break;
            case CilCode.Conv_U2: Conv(CilOpCodes.Conv_U2); break;
            case CilCode.Conv_U4: Conv(CilOpCodes.Conv_U4); break;
            case CilCode.Conv_U8: Conv(CilOpCodes.Conv_U8); break;
            case CilCode.Conv_R4: Conv(CilOpCodes.Conv_R4); break;
            case CilCode.Conv_R8: Conv(CilOpCodes.Conv_R8); break;
            case CilCode.Conv_R_Un: Conv(CilOpCodes.Conv_R_Un); break;

            case CilCode.Isinst: EvalIsinst(cil); break;

            case CilCode.Add: Binary(CilOpCodes.Add, (a, b) => a + b, ipCapable: true); break;
            case CilCode.Sub: Binary(CilOpCodes.Sub, (a, b) => a - b, ipCapable: true); break;
            case CilCode.Mul: Binary(CilOpCodes.Mul, (a, b) => a * b); break;
            case CilCode.Div: Binary(CilOpCodes.Div, (a, b) => b == 0 ? 0 : a / b); break;
            case CilCode.Div_Un: Binary(CilOpCodes.Div_Un, null); break;
            case CilCode.Rem: Binary(CilOpCodes.Rem, (a, b) => b == 0 ? 0 : a % b); break;
            case CilCode.Rem_Un: Binary(CilOpCodes.Rem_Un, null); break;
            case CilCode.And: Binary(CilOpCodes.And, (a, b) => a & b); break;
            case CilCode.Or: Binary(CilOpCodes.Or, (a, b) => a | b); break;
            case CilCode.Xor: Binary(CilOpCodes.Xor, (a, b) => a ^ b); break;
            case CilCode.Shl: Binary(CilOpCodes.Shl, (a, b) => a << (int)b); break;
            case CilCode.Shr: Binary(CilOpCodes.Shr, (a, b) => a >> (int)b); break;
            case CilCode.Shr_Un: Binary(CilOpCodes.Shr_Un, null); break;
            case CilCode.Neg: Unary(CilOpCodes.Neg); break;
            case CilCode.Not: Unary(CilOpCodes.Not); break;
            case CilCode.Ceq: CompareEqGeneral(); break;
            case CilCode.Clt: Compare(CilOpCodes.Clt, (a, b) => a < b); break;
            case CilCode.Clt_Un: Compare(CilOpCodes.Clt_Un, null); break;
            case CilCode.Cgt: Compare(CilOpCodes.Cgt, (a, b) => a > b); break;
            case CilCode.Cgt_Un: Compare(CilOpCodes.Cgt_Un, null); break;

            case CilCode.Newobj: EvalNewobj(cil.Operand as IMethodDescriptor); break;

            case CilCode.Call:
            case CilCode.Callvirt:
                DispatchCall(cil.Operand as IMethodDescriptor);
                break;

            case CilCode.Br:
            case CilCode.Br_S:
                next = Target(cil);
                break;

            case CilCode.Brtrue:
            case CilCode.Brtrue_S:
            {
                var cond = Pop();
                int jumpIp = Target(cil);
                if (cond is SymValue.Cond cc)
                    return StepCondBranch(cc, trueIp: jumpIp, falseIp: next, ref next);
                next = ResolveBranch(cond, jumpIp, next, wantTrue: true);
                break;
            }
            case CilCode.Brfalse:
            case CilCode.Brfalse_S:
            {
                var cond = Pop();
                int jumpIp = Target(cil);
                if (cond is SymValue.Cond cc)
                    return StepCondBranch(cc, trueIp: next, falseIp: jumpIp, ref next);
                next = ResolveBranch(cond, jumpIp, next, wantTrue: false);
                break;
            }
            case CilCode.Beq:
            case CilCode.Beq_S:
                next = ResolveEqBranch(Pop(), Pop(), Target(cil), next, wantEqual: true);
                break;
            case CilCode.Bne_Un:
            case CilCode.Bne_Un_S:
                next = ResolveEqBranch(Pop(), Pop(), Target(cil), next, wantEqual: false);
                break;
            case CilCode.Blt: case CilCode.Blt_S: case CilCode.Blt_Un: case CilCode.Blt_Un_S:
                next = ResolveRelBranch(Pop(), Pop(), Target(cil), next, (a, b) => a < b);
                break;
            case CilCode.Bgt: case CilCode.Bgt_S: case CilCode.Bgt_Un: case CilCode.Bgt_Un_S:
                next = ResolveRelBranch(Pop(), Pop(), Target(cil), next, (a, b) => a > b);
                break;
            case CilCode.Ble: case CilCode.Ble_S: case CilCode.Ble_Un: case CilCode.Ble_Un_S:
                next = ResolveRelBranch(Pop(), Pop(), Target(cil), next, (a, b) => a <= b);
                break;
            case CilCode.Bge: case CilCode.Bge_S: case CilCode.Bge_Un: case CilCode.Bge_Un_S:
                next = ResolveRelBranch(Pop(), Pop(), Target(cil), next, (a, b) => a >= b);
                break;

            case CilCode.Switch:
                if (TryEmitExceptionHandlerTerminator(cil))
                    return false;
                throw new LiftUnsupported("execute IL switch not modelled");

            case CilCode.Throw:
                // Preserve original-program throws, but keep rejecting unmodelled VM guard throws.
                EmitSemanticThrowOrReject();
                return false;

            case CilCode.Ret:
                return false;

            default:
                throw new LiftUnsupported($"execute IL opcode {cil.OpCode.Code} not modelled");
        }
        return true;
    }

    /// <summary>Resolves a branch on a genuine VM comparison result, then continues or stops
    /// depending on whether the resolution was a local materialisation or a full branch emission.</summary>
    private bool StepCondBranch(SymValue.Cond cond, int trueIp, int falseIp, ref int next)
    {
        if (TryMaterializeTernary(cond, trueIp, falseIp, out int convergeIp, out var merged))
        {
            _eval.Push(merged);
            next = convergeIp;
            return true;
        }
        if (TryResolveOpenBranch(cond, trueIp, falseIp))
            return false; // _termKind is now Resolved; Run()/the caller's loop stops here.
        throw new LiftUnsupported($"branch on comparison result ({cond.Rel}) does not match a supported shape");
    }

    private int Target(CilInstruction cil)
        => cil.Operand is ICilLabel l && _offsetToIndex.TryGetValue((int)l.Offset, out var i) ? i
           : throw new LiftUnsupported("unresolved execute-IL branch target");

    private static int ArgIndex(CilInstruction i) => i.Operand is Parameter p ? p.Index : Convert.ToInt32(i.Operand ?? 0);
    private static int LocalIndex(CilInstruction i) => i.Operand is CilLocalVariable l ? l.Index : Convert.ToInt32(i.Operand ?? 0);
    private SymValue Local(int i) => _locals.TryGetValue(i, out var v) ? v : new SymValue.Unknown("uninit-local");
    private static SymValue Int(int v) => new SymValue.Operand(v);
    private SymValue Pop() => _eval.Count > 0 ? _eval.Pop() : new SymValue.Unknown("pop-empty");

    private TypeSignature? CastTargetType(CilInstruction cil)
    {
        if (cil.Operand is not ITypeDefOrRef t) return null;
        return TypeSignatureOf(t);
    }

    /// <summary>
    /// Converts a metadata type descriptor to its real signature without resolving away a
    /// TypeSpecification. Resolving a GenericInstance TypeSpec first would collapse e.g.
    /// Dictionary&lt;String,String&gt; to the open Dictionary&lt;,&gt; TypeDef and poison every later
    /// local-read cast inferred from that value.
    /// </summary>
    private TypeSignature? TypeSignatureOf(ITypeDescriptor type)
    {
        try
        {
            return type switch
            {
                TypeSpecification specification => specification.ToTypeSignature(),
                ITypeDefOrRef typeDefOrRef when ResolveTypeDef(typeDefOrRef) is { } definition
                    => typeDefOrRef.ToTypeSignature(definition.IsValueType),
                _ => null,
            };
        }
        catch { return null; }
    }
}
