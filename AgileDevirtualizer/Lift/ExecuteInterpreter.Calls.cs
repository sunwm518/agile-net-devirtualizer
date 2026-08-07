using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Lift;

// Call dispatch: vocabulary stack/ctx ops, reflection-anchored helpers, reflection accessors, and
// a transparent fallback that keeps the model balanced for VM bookkeeping calls we needn't emit.
internal sealed partial class ExecuteInterpreter
{
    private void DispatchCall(IMethodDescriptor? m)
    {
        if (m is null)
            throw new LiftUnsupported("call to a null method descriptor");
        var def = ResolveM(m);

        if (TryHandleDefaultValueCall(m, def))
            return;

        if (TryHandleCurrentExceptionAccessor(m, def))
            return;

        // --- VM context / evaluation-stack vocabulary ---
        if (Same(def, _vocab.GetStack)) { Pop(); _eval.Push(new SymValue.StackRef()); return; }
        if (Same(def, _vocab.GetLocals)) { Pop(); _eval.Push(new SymValue.SlotArray(false)); return; }
        if (Same(def, _vocab.GetArgs)) { Pop(); _eval.Push(new SymValue.SlotArray(true)); return; }
        if (Same(def, _vocab.GetIp)) { Pop(); _eval.Push(new SymValue.Ip(0)); return; }
        if (Same(def, _vocab.Pop))
        {
            Pop();
            var value = _vmValueTypes.Count > 0 ? _vmValueTypes.Pop() : default;
            _eval.Push(new SymValue.OnStack(value.Type, ManagedPointer: value.ManagedPointer,
                KnownNull: value.KnownNull));
            return;
        }
        if (Same(def, _vocab.Peek))
        {
            Pop();
            var value = _vmValueTypes.Count > 0 ? _vmValueTypes.Peek() : default;
            _eval.Push(new SymValue.OnStack(value.Type, Peeked: true, ManagedPointer: value.ManagedPointer,
                KnownNull: value.KnownNull));
            return;
        }
        if (_vocab.Push.Any(p => Same(def, p))) { DoVmPush(m); return; }
        if (Same(def, _vocab.SetLocal)) { DoSetLocal(); return; }
        if (Same(def, _vocab.SetIp)) { DoSetIp(); return; }
        if (Same(def, _vocab.SetReturn)) { Pop(); Pop(); _returnOnStack = true; return; }

        // --- reflection-anchored runtime helpers ---
        switch (_helpers.RoleOf(m))
        {
            case HelperRole.ResolveMethod: DoResolve(m, HelperRole.ResolveMethod); return;
            case HelperRole.ResolveField: DoResolve(m, HelperRole.ResolveField); return;
            case HelperRole.ResolveType: DoResolve(m, HelperRole.ResolveType); return;
            case HelperRole.ResolveString: DoResolveString(m); return;
            case HelperRole.ResolveMember: DoResolve(m, HelperRole.ResolveMember); return;
            case HelperRole.Invoke: DoInvoke(m); return;
            case HelperRole.NewObj: DoNewObj(m); return;
            case HelperRole.FieldSet: DoFieldAccess(store: true); return;
            case HelperRole.FieldGet: DoFieldAccess(store: false); return;
            case HelperRole.CoerceByRef: DoCoerceByRef(m); return;
        }

        // --- VM comparison primitives (is-zero / eq / lt / …), identified by probing ---
        if (_conditions.Relation(m) is { } rel)
        {
            int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
            var args = new SymValue[pc];
            for (int i = pc - 1; i >= 0; i--) args[i] = Pop();
            // Most operands (the compared values) are already real stack values from earlier
            // emissions (field loads, pushes, …); an inline constant argument baked into the
            // comparison call itself (e.g. an ordering-mode enum) is NOT — materialise it now, in
            // order, so the call below receives exactly the arguments the runtime would have.
            // Comparison primitives are always static (probed via concrete int inputs), so the
            // parameter types line up with `args` directly — no "this" slot to account for.
            if (TryEmitNativeStackComparison(rel, args))
            {
                _eval.Push(new SymValue.Cond(rel));
                return;
            }
            EmitArgsBoxed(args, m.Signature!.ParameterTypes);
            Emit(CilOpCodes.Call, m);
            _eval.Push(new SymValue.Cond(rel));
            return;
        }

        // --- System.Array operations map to newarr / ldlen / ldelem / stelem ---
        if (TryArrayOp(m))
            return;

        // --- reflection accessors the handler branches on (evaluated concretely) ---
        if (TryReflectionAccessor(m))
            return;

        // --- value-wrapper accessors (hn4=.Value / conversions / storage-kind) ---
        if (def is { IsStatic: false } && ReferenceEquals(def.DeclaringType, _vocab.ValueType) && ParamCount(m) == 0)
        {
            HandleValueAccessor(m);
            return;
        }

        // --- anything else is VM bookkeeping: balance the model and move on ---
        Transparent(m);
    }

    /// <summary>
    /// A parameterless accessor on the boxed-value wrapper: one returning the object is the value
    /// itself (pass through); one returning a primitive is a numeric conversion (emit conv on real
    /// stack values); anything else (storage-kind enum, Type, …) is bookkeeping metadata.
    /// </summary>
    private void HandleValueAccessor(IMethodDescriptor m)
    {
        var ret = SigReturn(m);
        if (ret is null || ret.IsTypeOf("System", "Object"))
            return; // the value passes through unchanged

        // A storage-coercion accessor that returns the wrapper type itself (observed: normalizing an
        // IntPtr/UIntPtr-boxed value to the platform's native int/long/uint/ulong before a numeric-kind
        // dispatch) — it either returns `this` unchanged or rewraps the SAME logical value in a new
        // wrapper instance. Our model already represents the real underlying value directly (not the
        // wrapper), so the coercion is a no-op for our purposes: leave the receiver as the result.
        if (ResolveTypeDef(ret) is { } retDef && ReferenceEquals(retDef, _vocab.ValueType))
            return;

        // The "GetType of the underlying value" accessor: the runtime uses `value.GetType() ==
        // typeof(X)` to dispatch between numeric-conversion overloads — resolve it concretely from
        // the receiver's known type (tracked via the VM eval-stack shadow) rather than treat it as
        // unknowable bookkeeping.
        if (ret.IsTypeOf("System", "Type"))
        {
            var recv = Pop();
            _eval.Push(recv is SymValue.OnStack { KnownType: { } kt }
                ? new SymValue.Operand(kt)
                : new SymValue.Unknown("gettype-unknown"));
            return;
        }

        if (ConvOpFor(ret) is { } conv)
        {
            var recv = Pop();
            if (IsStack(recv)) { Emit(conv); _eval.Push(new SymValue.OnStack(ret)); }
            else _eval.Push(recv); // converting a decoded constant: keep it for folding
            return;
        }

        Pop();
        _eval.Push(new SymValue.Unknown("valacc-meta")); // storage kind etc.
    }

    private static CilOpCode? ConvOpFor(TypeSignature t)
    {
        if (t.IsTypeOf("System", "SByte")) return CilOpCodes.Conv_I1;
        if (t.IsTypeOf("System", "Byte")) return CilOpCodes.Conv_U1;
        if (t.IsTypeOf("System", "Int16")) return CilOpCodes.Conv_I2;
        if (t.IsTypeOf("System", "UInt16")) return CilOpCodes.Conv_U2;
        if (t.IsTypeOf("System", "Int32")) return CilOpCodes.Conv_I4;
        if (t.IsTypeOf("System", "UInt32")) return CilOpCodes.Conv_U4;
        if (t.IsTypeOf("System", "Int64")) return CilOpCodes.Conv_I8;
        if (t.IsTypeOf("System", "UInt64")) return CilOpCodes.Conv_U8;
        if (t.IsTypeOf("System", "Single")) return CilOpCodes.Conv_R4;
        if (t.IsTypeOf("System", "Double")) return CilOpCodes.Conv_R8;
        if (t.IsTypeOf("System", "IntPtr")) return CilOpCodes.Conv_I;
        if (t.IsTypeOf("System", "UIntPtr")) return CilOpCodes.Conv_U;
        return null;
    }

    private void EvalNewobj(IMethodDescriptor? ctor)
    {
        int pc = ctor is null ? 0 : ParamCount(ctor);
        var args = new SymValue[pc];
        for (int i = pc - 1; i >= 0; i--) args[i] = Pop();

        // (VM slots array, index) → the "address of a VM slot" wrapper (structural: no name needed).
        if (pc == 2 && args[0] is SymValue.SlotArray sa && TryInt(args[1], out int idx))
        {
            _eval.Push(new SymValue.SlotAddr(sa.IsArgs, idx));
            return;
        }

        // The SAME by-ref wrapper also supports constructing "address of an arbitrary array element"
        // (not just a VM local/arg slot): `new Wrapper(array, index)` — detected structurally by the
        // ctor's OWN declared parameter type (System.Array), not by the argument's runtime shape,
        // since the array/index here are genuine runtime values, not VM slot markers.
        if (pc == 2 && ctor?.Signature is { ParameterTypes.Count: 2 } sig && sig.ParameterTypes[0].IsTypeOf("System", "Array"))
        {
            _eval.Push(new SymValue.ArrayElemAddr(args[0], args[1]));
            return;
        }

        // A handler only news up VM-internal objects; the boxed-value wrapper forwards its value.
        var dt = ResolveTypeDef(ctor?.DeclaringType);
        _eval.Push(dt is not null && ReferenceEquals(dt, _vocab.ValueType) && pc >= 1 ? args[0] : new SymValue.Unknown("newobj-nonvalue"));
    }

    /// <summary>Recognizes the reflection form of array ops the VM uses and emits newarr/ldlen/ldelem/stelem.</summary>
    private bool TryArrayOp(IMethodDescriptor m)
    {
        if ((m.DeclaringType?.Namespace?.ToString() ?? "") != "System" || (m.DeclaringType?.Name?.ToString() ?? "") != "Array")
            return false;

        switch (m.Name?.ToString())
        {
            case "CreateInstance":
            {
                int pc = ParamCount(m);
                var args = new SymValue[pc];
                for (int i = pc - 1; i >= 0; i--) args[i] = Pop();
                // 1-D array: CreateInstance(Type, int) → newarr <elementType>. The length may already
                // be a real value on the CIL stack, or still just a symbolic constant/expression —
                // EmitPush materialises whichever it is (a no-op for an already-live OnStack value).
                var type = args.OfType<SymValue.Resolved>().FirstOrDefault(r => r.Kind == HelperRole.ResolveType);
                if (pc == 2 && type?.Member is ITypeDefOrRef et)
                {
                    EmitPush(args[1]);
                    Emit(CilOpCodes.Newarr, et);
                    var elemSig = et.ToTypeSignature(ResolveTypeDef(et)?.IsValueType ?? false);
                    _eval.Push(new SymValue.OnStack(new SzArrayTypeSignature(elemSig)));
                    return true;
                }
                _eval.Push(new SymValue.Unknown("array-createinstance"));
                return true;
            }
            case "get_Length":
            {
                var arr = Pop();
                if (IsStack(arr)) { Emit(CilOpCodes.Ldlen); Emit(CilOpCodes.Conv_I4); _eval.Push(new SymValue.OnStack(_module.CorLibTypeFactory.Int32)); }
                else _eval.Push(new SymValue.Unknown("array-length-bookkeeping"));
                return true;
            }
            case "GetValue":
            {
                // arr.GetValue(int index): stack is already [array, index] top-to-bottom-reversed,
                // matching ldelem's expected [array, index] layout — no reordering needed.
                var idx = Pop();
                var arr = Pop();
                if (IsStack(arr) && IsStack(idx))
                {
                    var elemType = ArrayElementType(KnownTypeOf(arr));
                    Emit(LdelemOpFor(elemType));
                    _eval.Push(new SymValue.OnStack(elemType));
                }
                else _eval.Push(new SymValue.Unknown("array-getvalue-bookkeeping"));
                return true;
            }
            case "SetValue":
            {
                // arr.SetValue(value, index): stack is already [array, index, value]
                // top-to-bottom-reversed, matching stelem's expected [array, index, value] layout —
                // no reordering needed (same reasoning as GetValue above).
                var value = Pop();
                var idx = Pop();
                var arr = Pop();
                if (IsStack(arr) && IsStack(idx) && IsStack(value))
                {
                    Emit(StelemOpFor(ArrayElementType(KnownTypeOf(arr))));
                }
                else
                {
                    // SetValue is void; any operand that WAS genuinely materialised on the real
                    // stack must still be discarded explicitly, or it leaks through as an orphaned,
                    // unbalancing value (same failure mode fixed earlier for DoVmPush).
                    if (IsStack(value)) Emit(CilOpCodes.Pop);
                    if (IsStack(idx)) Emit(CilOpCodes.Pop);
                    if (IsStack(arr)) Emit(CilOpCodes.Pop);
                }
                return true;
            }
        }
        return false;
    }

    private static TypeSignature? ArrayElementType(TypeSignature? arrayType) =>
        (arrayType as SzArrayTypeSignature)?.BaseType;

    private static CilOpCode LdelemOpFor(TypeSignature? t)
    {
        if (t is null) return CilOpCodes.Ldelem_Ref;
        if (t.IsTypeOf("System", "SByte")) return CilOpCodes.Ldelem_I1;
        if (t.IsTypeOf("System", "Byte") || t.IsTypeOf("System", "Boolean")) return CilOpCodes.Ldelem_U1;
        if (t.IsTypeOf("System", "Int16")) return CilOpCodes.Ldelem_I2;
        if (t.IsTypeOf("System", "UInt16") || t.IsTypeOf("System", "Char")) return CilOpCodes.Ldelem_U2;
        if (t.IsTypeOf("System", "Int32")) return CilOpCodes.Ldelem_I4;
        if (t.IsTypeOf("System", "UInt32")) return CilOpCodes.Ldelem_U4;
        if (t.IsTypeOf("System", "Int64") || t.IsTypeOf("System", "UInt64")) return CilOpCodes.Ldelem_I8;
        if (t.IsTypeOf("System", "Single")) return CilOpCodes.Ldelem_R4;
        if (t.IsTypeOf("System", "Double")) return CilOpCodes.Ldelem_R8;
        if (t.IsTypeOf("System", "IntPtr") || t.IsTypeOf("System", "UIntPtr")) return CilOpCodes.Ldelem_I;
        return CilOpCodes.Ldelem_Ref;
    }

    private static CilOpCode StelemOpFor(TypeSignature? t)
    {
        if (t is null) return CilOpCodes.Stelem_Ref;
        if (t.IsTypeOf("System", "SByte") || t.IsTypeOf("System", "Byte") || t.IsTypeOf("System", "Boolean")) return CilOpCodes.Stelem_I1;
        if (t.IsTypeOf("System", "Int16") || t.IsTypeOf("System", "UInt16") || t.IsTypeOf("System", "Char")) return CilOpCodes.Stelem_I2;
        if (t.IsTypeOf("System", "Int32") || t.IsTypeOf("System", "UInt32")) return CilOpCodes.Stelem_I4;
        if (t.IsTypeOf("System", "Int64") || t.IsTypeOf("System", "UInt64")) return CilOpCodes.Stelem_I8;
        if (t.IsTypeOf("System", "Single")) return CilOpCodes.Stelem_R4;
        if (t.IsTypeOf("System", "Double")) return CilOpCodes.Stelem_R8;
        if (t.IsTypeOf("System", "IntPtr") || t.IsTypeOf("System", "UIntPtr")) return CilOpCodes.Stelem_I;
        return CilOpCodes.Stelem_Ref;
    }

    private void DoVmPush(IMethodDescriptor push)
    {
        int pc = ParamCount(push);
        var args = new SymValue[pc];
        for (int i = pc - 1; i >= 0; i--) args[i] = Pop();
        Pop(); // the stack `this`
        _vmValueTypes.Push(new VmStackType(KnownTypeOf(args[0]),
            IsManagedPointerValue(args[0]), IsKnownNullValue(args[0])));
        EmitPush(args[0]);
        // The optional trailing argument (an explicit storage-kind enum) is metadata our model
        // doesn't need — but if computing it involved a genuinely emitted call (e.g. a storage-kind
        // helper we now eagerly replay), that real value is still sitting on the stack and MUST be
        // discarded explicitly, or it leaks through as an orphaned, unbalancing value.
        for (int i = 1; i < pc; i++)
            if (IsStack(args[i])) Emit(CilOpCodes.Pop);
    }

    /// <summary>
    /// The CLR type of a value about to be pushed onto the VM's eval stack, when derivable — from a
    /// VM local/argument's declared type, or a boxed constant's own type. Never guessed: unknown
    /// stays null, and null propagates safely (a type-check on it just can't be resolved concretely).
    /// </summary>
    private TypeSignature? KnownTypeOf(SymValue v) => v switch
    {
        SymValue.OnStack os => os.KnownType,
        SymValue.SlotRead { IsArgs: false } sr => _vmLocalKnownTypes.TryGetValue(sr.Index, out var dyn) ? dyn : DeclaredType(_vmLocalTypes, sr.Index),
        SymValue.SlotRead { IsArgs: true } sr => DeclaredType(_vmArgTypes, sr.Index),
        // Taking a slot's address changes its stack representation to a managed pointer, but not the
        // identity of the pointed-to CLR type. Keep that type in the VM stack shadow so a later
        // reflective call to an Object/interface virtual on this address can become constrained. T.
        SymValue.SlotAddr { IsArgs: false } sa => _vmLocalKnownTypes.TryGetValue(sa.Index, out var dyn) ? dyn : DeclaredType(_vmLocalTypes, sa.Index),
        SymValue.SlotAddr { IsArgs: true } sa => DeclaredType(_vmArgTypes, sa.Index),
        SymValue.ArrayElemAddr element => ArrayElementType(KnownTypeOf(element.Array)),
        SymValue.HandlerLocalAddr address => KnownTypeOf(address.Value),
        SymValue.Operand { Value: { } val } => CorLibTypeOf(val),
        SymValue.Constant { Value: { } val } => CorLibTypeOf(val),
        SymValue.ResolvedString => _module.CorLibTypeFactory.String,
        SymValue.DefaultValue value => value.Type,
        SymValue.Cond => _module.CorLibTypeFactory.Boolean,
        _ => null,
    };

    /// <summary>
    /// Preserves a managed-pointer stack shape when a by-ref value is wrapped, popped and pushed
    /// through Agile's value stack more than once. The first push commonly sees a SlotAddr marker;
    /// later pushes see the equivalent OnStack value, whose pointer flag is just as authoritative.
    /// </summary>
    private static bool IsManagedPointerValue(SymValue value) => value switch
    {
        SymValue.SlotAddr or SymValue.ArrayElemAddr => true,
        SymValue.OnStack { ManagedPointer: true } => true,
        SymValue.HandlerLocalAddr address => IsManagedPointerValue(address.Value),
        _ => false,
    };

    /// <summary>
    /// Emits a full argument list in call order, boxing any argument that is a genuine value type
    /// (a constant, a comparison result, a tracked-known value-type receiver, …) but whose declared
    /// parameter expects a reference type — needed whenever we re-emit a raw eager call (comparison
    /// primitives, safe Transparent calls, a VM local store) since <see cref="EmitPush"/> alone only
    /// materialises a value, it never adapts it to a target signature.
    ///
    /// <c>box</c> only ever operates on the CURRENT TOP of the real stack. Once more than one
    /// argument has been pushed, an earlier one sits buried beneath later ones, so boxing it in
    /// place is impossible without disturbing the others — naively emitting "push arg0; box arg0;
    /// push arg1; box arg1" is only safe when arg0 needs no box, otherwise the second push (arg1)
    /// silently becomes the operand `box arg0`'s box instruction actually sees, corrupting both
    /// values. So instead: push everything first (in order — a no-op for a value already on the
    /// stack), then, from the top down, stash every argument above the deepest one needing a box
    /// into a scratch local, box in place once it's on top, and reload the stashed ones (boxing
    /// each in turn) in their original order.
    /// </summary>
    private void EmitArgsBoxed(IReadOnlyList<SymValue> values, IList<TypeSignature> paramTypes)
    {
        int n = values.Count;
        var boxType = new TypeSignature?[n];
        for (int i = 0; i < n; i++)
            boxType[i] = !paramTypes[i].IsValueType && KnownTypeOf(values[i]) is { IsValueType: true } vt ? vt : null;

        for (int i = 0; i < n; i++)
            EmitPush(values[i]);

        if (Array.TrueForAll(boxType, t => t is null))
            return; // fast path: nothing needs boxing, no reordering required

        var temps = new int[n];
        for (int i = n - 1; i >= 1; i--)
        {
            temps[i] = AllocTemp(KnownTypeOf(values[i]) ?? _module.CorLibTypeFactory.Object);
            Emit(CilOpCodes.Stloc, new TempLocalRef(temps[i]));
        }
        if (boxType[0] is { } bt0) Emit(CilOpCodes.Box, bt0.ToTypeDefOrRef());
        for (int i = 1; i < n; i++)
        {
            Emit(CilOpCodes.Ldloc, new TempLocalRef(temps[i]));
            if (boxType[i] is { } bti) Emit(CilOpCodes.Box, bti.ToTypeDefOrRef());
        }
    }

    private static TypeSignature? DeclaredType(IReadOnlyList<TypeSignature> list, int index) =>
        index >= 0 && index < list.Count ? list[index] : null;

    private TypeSignature? CorLibTypeOf(object val)
    {
        var f = _module.CorLibTypeFactory;
        return val switch
        {
            bool => f.Boolean, char => f.Char, sbyte => f.SByte, byte => f.Byte,
            short => f.Int16, ushort => f.UInt16, int => f.Int32, uint => f.UInt32,
            long => f.Int64, ulong => f.UInt64, float => f.Single, double => f.Double,
            string => f.String, IntPtr => f.IntPtr, UIntPtr => f.UIntPtr,
            _ => null,
        };
    }

    private void DoSetLocal()
    {
        var value = Pop();
        int index = AsInt(Pop());
        Pop(); // ctx
        TypeSignature? declared = DeclaredType(_vmLocalTypes, index);
        value = DereferenceManagedPointerForLocalStore(value, declared);
        TypeSignature? known = KnownTypeOf(value);
        bool narrowObjectToDeclared = declared is not null
            && IsConcreteReferenceType(declared)
            && known?.IsTypeOf("System", "Object") == true;
        // Materialise (and box, if the slot is declared as a reference type but we're storing a
        // genuine value type) before storing — a no-op for the common case where value is already
        // on the real stack in a shape matching the slot's declared type.
        if (declared is not null) EmitArgsBoxed([value], [declared]);
        else EmitPush(value);
        // Reflection converted an Object-returning producer before assigning it to this concrete
        // reference slot. Native stloc needs that conversion explicitly, and later reads should
        // inherit the narrowed type rather than the producer's weaker Object signature.
        if (narrowObjectToDeclared)
            Emit(CilOpCodes.Castclass, declared!.ToTypeDefOrRef());
        Emit(CilOpCodes.Stloc, index);
        // Track the ACTUAL type stored, not the slot's generic declared type (see KnownTypeOf). A
        // branch that stores a literal `null` carries NO type information of its own (null is valid
        // for any reference type) — it must not clobber a more specific type already learned from a
        // SIBLING branch writing the same local (e.g. an if/else where one arm assigns a real
        // `Byte[]` result and the other assigns `null`). The priming pass (see
        // ExecuteInterpreter.BeginMethod) walks every VM instruction once, in index order,
        // regardless of which branch actually runs at runtime, so plain "last write wins" would let
        // the null-arm's lack of type info silently erase real information the other arm already
        // provided, whichever branch happens to have the higher instruction index.
        if (narrowObjectToDeclared)
            _vmLocalKnownTypes[index] = declared;
        else if (known is { } kt)
            _vmLocalKnownTypes[index] = kt;
        else if (!_vmLocalKnownTypes.ContainsKey(index))
            _vmLocalKnownTypes[index] = null;
    }

    private void DoSetIp()
    {
        var arg = Pop();
        Pop(); // ctx
        // Record the pending terminator; the last SetIp before the handler returns is the real one.
        switch (arg)
        {
            case SymValue.Ip ip:
                _termKind = TermKind.Branch;
                _termTarget = _instr.Index + 1 + ip.Offset;
                break;
            case SymValue.SwitchTable st:
                _termKind = TermKind.Switch;
                _termSwitch = st.Deltas.Select(d => new VmTarget(_instr.Index + 1 + st.Base + d)).ToArray();
                break;
            case SymValue.Operand { Value: { } v } when IsIntLike(v):
                // An absolute IP (e.g. int.MaxValue) drives the dispatch loop out of range = return.
                _termKind = TermKind.Return;
                break;
            default:
                throw new LiftUnsupported($"setIp with unmodelled value {arg}");
        }
    }

    private void DoResolve(IMethodDescriptor m, HelperRole role)
    {
        int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
        object? token = null;
        for (int i = 0; i < pc; i++)
        {
            var a = Pop();
            if (a is SymValue.Operand { Value: { } tv } && IsIntLike(tv)) token = tv;
        }
        var member = token is null ? null : LookupToken(token);
        // Module.ResolveMember doesn't say in advance whether the token is a field or a method — the
        // CLR itself decides that by looking at the referenced member's own signature (a field sig vs.
        // a method sig), so we do the same here rather than guessing, letting every downstream check
        // that matches on Kind:ResolveField/ResolveMethod treat this identically to a direct
        // Module.ResolveField/ResolveMethod call.
        if (role == HelperRole.ResolveMember)
            role = ClassifyMember(member);
        _eval.Push(new SymValue.Resolved(role, member));
    }

    private static HelperRole ClassifyMember(IMetadataMember? member) => member switch
    {
        FieldDefinition => HelperRole.ResolveField,
        MethodDefinition => HelperRole.ResolveMethod,
        MemberReference { Signature: FieldSignature } => HelperRole.ResolveField,
        MemberReference { Signature: MethodSignature } => HelperRole.ResolveMethod,
        TypeDefinition or TypeReference or TypeSpecification => HelperRole.ResolveType,
        _ => HelperRole.None,
    };

    private void DoResolveString(IMethodDescriptor m)
    {
        int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
        object? token = null;
        for (int i = 0; i < pc; i++)
        {
            var a = Pop();
            if (a is SymValue.Operand { Value: { } tv } && IsIntLike(tv)) token = tv;
        }
        uint rawToken = token is null ? 0 : Convert.ToUInt32(token);
        string? s = token is not null && _module.TryLookupString(new MetadataToken(rawToken), out var us)
            ? us : null;
        _eval.Push(s is null
            ? new SymValue.Operand(null)
            : new SymValue.ResolvedString(s, rawToken));
    }

    private void DoInvoke(IMethodDescriptor m)
    {
        int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
        var popped = new SymValue[pc];
        for (int i = 0; i < pc; i++) popped[i] = Pop();

        var method = popped.OfType<SymValue.Resolved>().FirstOrDefault(r => r.Kind == HelperRole.ResolveMethod);
        if (method?.Member is not IMethodDescriptor target)
            throw new LiftUnsupported("invoke without a resolved method operand");

        // Agile stores the virtual-call flag as the wrapper's trailing bool parameter.
        bool isVirtual = LastParamIsBool(m) && AsBool(popped[0]);

        // `target`'s real arguments were pushed for real by ordinary VM value reads earlier in this
        // same fused handler and are still sitting untouched on the real CIL stack exactly where
        // this direct call needs them (the runtime's own args-array bookkeeping in between —
        // `OX4=`/`Pn4=`, decompiled straight from the runtime DLL — is never emitted at all, since
        // it has byref out-parameters). Almost always this needs no attention at all: a value's own
        // real CIL shape already matches what `target`'s parameter expects (e.g. a raw literal
        // Int32 flowing straight into `Math.Abs(Int32)`).
        //
        // It breaks in exactly one shape: a value-type RESULT of a PRIOR invoke dispatched through
        // this same DoInvoke, within this same fused block, chaining straight into THIS invoke as
        // its LAST argument, when that argument is declared as a reference type. Real reflection
        // would have kept such a value boxed the entire way through (`.GetType()` inside the
        // runtime's own coercion helper, confirmed by decompiling it, requires a boxed receiver —
        // reflection only unboxes at the very last moment, inside the reflective Invoke call
        // itself); our direct-call optimization skips all of that, so the value is genuinely still
        // raw here. The one place we can look for it is the IMMEDIATE top of `_eval` (the prior
        // invoke's own `Push` at the end of ITS OWN DoInvoke — nothing else ever consumes it, since
        // the args-array bookkeeping is opaque to us) — never deeper, since anything further down
        // could be an unrelated, stale leftover from earlier bookkeeping we have no way to attribute
        // reliably (confirmed via a read-only probe: `_eval`'s 2nd-from-top entry at this exact kind
        // of call site was, in one observed case, a completely unrelated earlier value). A plain
        // `Peek` (no pop) keeps this fix a pure addition — it can never disturb the existing,
        // working "trust the stack" path for every other invoke.
        if (target.Signature is { ParameterTypes.Count: > 0 } sig
            && !sig.ParameterTypes[^1].IsValueType
            && _eval.Count > 0
            && HandlerLocalValue(_eval.Peek()) is SymValue.OnStack
                { KnownType: { IsValueType: true } vt, ManagedPointer: false }
            && TailCanCarryValueType(vt))
        {
            Emit(CilOpCodes.Box, vt.ToTypeDefOrRef());
        }

        // Reflection accepts a boxed value-type receiver for Object/interface virtual dispatch. The
        // original CIL shape represented by Agile's by-ref slot wrapper is instead `ldloca T;
        // constrained. T; callvirt ...`. Once the address has travelled through the VM stack, its
        // KnownType is the only structural evidence left. For a parameterless call the top symbolic
        // value is unambiguously the receiver; emit the CLR prefix rather than an invalid direct
        // callvirt on a managed pointer. Calls with arguments need the broader real-stack shadow and
        // are intentionally left to that control-flow-aware work instead of guessed here.
        TypeSignature? constrainedReceiver = null;
        if (isVirtual && ParamCount(target) == 0 && _eval.Count > 0
            && HandlerLocalValue(_eval.Peek()) is SymValue.OnStack
                { KnownType: { IsValueType: true } valueType, ManagedPointer: true })
            constrainedReceiver = valueType;

        NarrowReferenceArguments(target);
        if (constrainedReceiver is null)
            NarrowReceiver(target);
        if (constrainedReceiver is not null)
            Emit(CilOpCodes.Constrained, constrainedReceiver.ToTypeDefOrRef());
        Emit(isVirtual ? CilOpCodes.Callvirt : CilOpCodes.Call, target);

        var retType = SigReturn(target);
        bool nonVoid = !(retType?.IsTypeOf("System", "Void") ?? true);
        _eval.Push(nonVoid ? new SymValue.OnStack(retType) : new SymValue.Void());
    }

    /// <summary>
    /// Inserts a <c>castclass target.DeclaringType</c> on the receiver of an instance-method invoke.
    /// The runtime passes a reflective call's receiver as <c>Object</c> (it dispatches dynamically),
    /// so our direct <c>call</c>/<c>callvirt</c> replacement gets a receiver typed only as whatever
    /// pushed it (often <c>Object</c>, e.g. an event <c>sender</c>) — too weak for the verifier, which
    /// demands the declaring type. Because reflection already invoked this exact method on the value,
    /// the value is provably an instance of the declaring type, so the cast is always runtime-safe.
    ///
    /// The receiver sits buried beneath the target's own arguments on the real stack. Those args were
    /// all just pushed in this same straight-line run of <c>_out</c> (no branch between a receiver push
    /// and its call), so a backward net-stack walk locates the boundary: consume exactly the arg
    /// values off the top, and the next slot down is the receiver — insert the cast right there,
    /// before the first arg. Aborts silently (leaving output unchanged) if the boundary can't be
    /// pinned down exactly, so a shape we don't understand is never mis-edited.
    /// </summary>
    private void NarrowReceiver(IMethodDescriptor target)
    {
        if (target.Signature is not { HasThis: true }) return;
        if (target.DeclaringType is not { } dt) return;
        if (ResolveTypeDef(dt) is not { IsValueType: false }) return;   // ref types only; must resolve
        if (dt.IsTypeOf("System", "Object")) return;                    // castclass Object is pointless

        // Only public targets. Narrowing the receiver to the declaring type re-types it as exactly
        // that type — verifiable for a public method from anywhere, but for a protected/internal one
        // the legality depends on the receiver's ORIGINAL (often more-derived) static type: e.g. a
        // form's `this` may legally call the protected `Control.set_DoubleBuffered`, but the same call
        // on a receiver re-typed to the base `Control` is a protected-access violation. When the
        // method isn't provably public (unresolved, or non-public), leave the receiver untouched.
        if (ResolveM(target) is not { IsPublic: true }) return;

        int args = ParamCount(target);
        int pos = _out.Count, net = 0;
        while (pos > 0 && net < args)
        {
            var op = _out[pos - 1].OpCode.Code;
            if (op is CilCode.Br or CilCode.Brtrue or CilCode.Brfalse or CilCode.Switch or CilCode.Ret)
                return; // crossed control flow — the tail isn't straight-line, can't trust the walk
            int d = NetDelta(_out[pos - 1]);
            if (d == int.MinValue) return; // effect unknown — abort rather than mis-place the cast
            net += d;
            pos--;
        }
        if (net != args) return; // didn't land exactly on the arg/receiver boundary
        _out.Insert(pos, new LiftedOp(CilOpCodes.Castclass, dt));
    }

    private void DoNewObj(IMethodDescriptor m)
    {
        int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
        var popped = new SymValue[pc];
        for (int i = 0; i < pc; i++) popped[i] = Pop();
        var ctor = popped.OfType<SymValue.Resolved>().FirstOrDefault(r => r.Kind == HelperRole.ResolveMethod);
        if (ctor?.Member is not IMethodDescriptor target)
            throw new LiftUnsupported("newobj without a resolved constructor operand");
        Emit(CilOpCodes.Newobj, target);
        // Preserve a constructed declaring TypeSpec exactly. ResolveTypeDef(...).ToTypeSignature()
        // would erase its generic arguments and turn Dictionary<String,String> into Dictionary<,>,
        // causing an invalid open-generic cast when the newly-created value is read from a VM local.
        _eval.Push(new SymValue.OnStack(
            target.DeclaringType is { } dt ? TypeSignatureOf(dt) : null));
    }

    private void DoFieldAccess(bool store)
    {
        // FieldInfo.SetValue(obj, value) / GetValue(obj): the FieldInfo is the call `this`.
        // Pop the BCL arguments, then the FieldInfo receiver.
        int extra = store ? 2 : 1;
        for (int i = 0; i < extra; i++) Pop();
        var field = Pop();
        if (field is not SymValue.Resolved { Kind: HelperRole.ResolveField, Member: IFieldDescriptor f })
            throw new LiftUnsupported("field access without a resolved field operand");
        bool isStatic = FieldIsStatic(f);
        if (store)
            Emit(isStatic ? CilOpCodes.Stsfld : CilOpCodes.Stfld, f);
        else
        {
            Emit(isStatic ? CilOpCodes.Ldsfld : CilOpCodes.Ldfld, f);
            _eval.Push(new SymValue.OnStack(FieldTypeOf(field) as TypeSignature));
        }
    }

    /// <summary>
    /// The fallback for a call that matches none of the recognised roles. Most such calls are VM
    /// bookkeeping operating on wrapper-typed/by-ref state we don't model faithfully (e.g. the
    /// coercion helpers that mutate a wrapper "in place"), so by default we just balance the model
    /// (pop args, push Unknown if non-void) without emitting. But a STATIC helper whose signature has
    /// NO by-ref parameters and NO wrapper-typed parameters operates purely on values our model
    /// already represents faithfully on the real stack (e.g. the numeric-conversion dispatchers) — for
    /// those we materialise the real arguments and eagerly replay the call, exactly like the
    /// comparison primitives, instead of giving up on whatever consumes its result.
    /// </summary>
    private void Transparent(IMethodDescriptor m)
    {
        int pc = ParamCount(m) + (HasThis(m) ? 1 : 0);
        var args = new SymValue[pc];
        for (int i = pc - 1; i >= 0; i--) args[i] = Pop();

        if (TryInlineRuntimeStackHelper(m, args))
            return;
        // Some grouped handlers call BCL metadata helpers directly rather than through one of the
        // runtime's own helper methods. Evaluate the same concrete Type facts here as the nested
        // runtime inliner does. Replaying them as live CIL loses the fact that, for example,
        // Nullable.GetUnderlyingType(aNonNullableEnum) is null and sends the handler down the wrong
        // coercion arm, which in turn erases the enum type needed by a later reflective invoke.
        string ns = m.DeclaringType?.Namespace?.ToString() ?? "";
        string declaringType = m.DeclaringType?.Name?.ToString() ?? "";
        string name = m.Name?.ToString() ?? "";
        if (TryEvaluateRuntimeMetadataCall(ns, declaringType, name, args, out var metadataResult))
        {
            if (metadataResult is not SymValue.Void)
                _eval.Push(metadataResult);
            return;
        }

        if (IsSafeToEagerlyEmit(m))
        {
            // Safe-to-eagerly-emit requires HasThis:false (see below), so args map 1:1 onto the
            // declared parameter types — no "this" slot to skip.
            EmitArgsBoxed(args, m.Signature!.ParameterTypes);
            Emit(CilOpCodes.Call, m);
            var retType = SigReturn(m);
            bool nonVoid = !(retType?.IsTypeOf("System", "Void") ?? true);
            _eval.Push(nonVoid ? new SymValue.OnStack(retType) : new SymValue.Void());
            return;
        }

        if (TryEagerInstanceValueCall(m, args))
            return;

        if (!(SigReturn(m)?.IsTypeOf("System", "Void") ?? true))
            _eval.Push(new SymValue.Unknown($"call {m.DeclaringType?.Name}.{m.Name}"));
    }

    /// <summary>
    /// An instance method on a genuine (non-wrapper) value type, called on a receiver we already
    /// track concretely on the real stack (e.g. <c>IntPtr.ToInt32()</c> called on a handler-own
    /// local produced by <c>unbox.any IntPtr</c>) — the same "pure value transform" spirit as
    /// <see cref="IsSafeToEagerlyEmit"/>'s static case, just with a by-ref receiver instead of a
    /// by-value argument. A value-type instance method always needs a managed-pointer receiver, so
    /// the already-pushed receiver value is stashed into a scratch local to take its address.
    /// </summary>
    private bool TryEagerInstanceValueCall(IMethodDescriptor m, SymValue[] args)
    {
        if (m.Signature is not { HasThis: true } sig) return false;
        if (ResolveTypeDef(m.DeclaringType) is not { IsValueType: true }) return false;
        if (args.Length == 0 || args[0] is not SymValue.OnStack { KnownType: { } recvType, ManagedPointer: false }) return false;
        foreach (var p in sig.ParameterTypes)
        {
            if (p is ByReferenceTypeSignature) return false;
            if (ResolveTypeDef(p) is { } pt && ReferenceEquals(pt, _vocab.ValueType)) return false;
        }

        int temp = AllocTemp(recvType);
        Emit(CilOpCodes.Stloc, new TempLocalRef(temp));
        Emit(CilOpCodes.Ldloca, new TempLocalRef(temp));
        EmitArgsBoxed(args[1..], sig.ParameterTypes);
        Emit(CilOpCodes.Call, m);
        var retType = SigReturn(m);
        bool nonVoid = !(retType?.IsTypeOf("System", "Void") ?? true);
        _eval.Push(nonVoid ? new SymValue.OnStack(retType) : new SymValue.Void());
        return true;
    }

    /// <summary>
    /// True for a static helper with no by-ref parameter and no parameter of the VM's wrapper type —
    /// i.e. one that transforms plain values (numbers, enums, strings, …) our model already tracks
    /// faithfully, rather than VM-internal wrapper/by-ref state we don't model.
    /// </summary>
    private bool IsSafeToEagerlyEmit(IMethodDescriptor m)
    {
        if (m.Signature is not { HasThis: false } sig) return false;
        foreach (var p in sig.ParameterTypes)
        {
            if (p is ByReferenceTypeSignature) return false;
            if (ResolveTypeDef(p) is { } pt && ReferenceEquals(pt, _vocab.ValueType)) return false;
        }
        return true;
    }

    /// <summary>
    /// The net stack effect (values pushed minus popped) of a single lifted op, derived from the
    /// opcode's declared stack behaviour — with the variable-behaviour call family (call/callvirt/
    /// newobj) computed from the target method's own signature. Returns <see cref="int.MinValue"/>
    /// for anything whose effect can't be determined here (e.g. a call op with no method operand, or
    /// <c>PopAll</c>), so callers can abort rather than mis-count. Used by the DoInvoke receiver
    /// narrowing to locate a buried receiver by walking the straight-line tail of <c>_out</c>.
    /// </summary>
    private int NetDelta(LiftedOp op)
    {
        int pop = BehaviourCount(op.OpCode.StackBehaviourPop);
        int push = BehaviourCount(op.OpCode.StackBehaviourPush);
        if (pop == VarBehaviour || push == VarBehaviour)
        {
            if (op.Operand is not IMethodDescriptor md || md.Signature is not { } s) return int.MinValue;
            bool isNewobj = op.OpCode.Code == CilCode.Newobj;
            int p = s.ParameterTypes.Count + (isNewobj ? 0 : s.HasThis ? 1 : 0);
            int q = isNewobj ? 1 : (SigReturn(md)?.IsTypeOf("System", "Void") ?? true) ? 0 : 1;
            return q - p;
        }
        if (pop < 0 || push < 0) return int.MinValue;
        return push - pop;
    }

    private const int VarBehaviour = -1;

    // Each non-zero fixed stack behaviour name lists one token per value it touches, joined by '_'
    // (e.g. Pop1 = 1, PopRef_PopI = 2, Push1_Push1 = 2); Pop0/Push0 = 0; Var* = variable (from the
    // operand's signature); anything else (PopAll) is unsupported here.
    private static int BehaviourCount(CilStackBehaviour b) => b switch
    {
        CilStackBehaviour.Pop0 or CilStackBehaviour.Push0 => 0,
        CilStackBehaviour.VarPop or CilStackBehaviour.VarPush => VarBehaviour,
        CilStackBehaviour.PopAll => int.MinValue,
        _ => b.ToString().Split('_').Length,
    };
}
