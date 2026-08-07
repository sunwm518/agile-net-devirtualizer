using AgileDevirtualizer.Decode;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Lift;

// Emission, reflection-fact evaluation, constant folding, and the guard-throw analysis that lets us
// step past the VM's runtime null/coercion checks (which are not part of the original method).
internal sealed partial class ExecuteInterpreter
{
    private void Emit(CilOpCode op, object? operand = null) => _out.Add(new LiftedOp(op, operand));

    private void PushHandlerField(CilInstruction cil)
    {
        Pop(); // the handler `this`
        var name = (cil.Operand as IFieldDescriptor)?.Name?.ToString();
        object? value = name is not null && _instr.Operands.TryGetValue(name, out var v) ? v : null;
        _eval.Push(value is DecodedStringLiteral decoded
            ? new SymValue.ResolvedString(decoded.Value, decoded.RawToken)
            : new SymValue.Operand(value));
    }

    /// <summary>Emits the CIL load that materialises a value the VM pushes onto its eval stack.</summary>
    private void EmitPush(SymValue value)
    {
        switch (value)
        {
            case SymValue.SlotRead sr:
                Emit(sr.IsArgs ? CilOpCodes.Ldarg : CilOpCodes.Ldloc, sr.Index);
                // VM locals are always declared generically (typically `object`) in their own
                // metadata table, so the verifier only sees that generic static type — but a
                // downstream consumer (e.g. ldelem/stelem/ldlen on a value we've dynamically tracked
                // as a specific array type) needs the ACTUAL type statically visible on the stack.
                // Narrow it here, right after the load, before anything else gets pushed on top.
                if (!sr.IsArgs && _vmLocalKnownTypes.TryGetValue(sr.Index, out var dynType) && dynType is { IsValueType: false })
                    Emit(CilOpCodes.Castclass, dynType.ToTypeDefOrRef());
                break;
            case SymValue.SlotAddr sa:
                Emit(sa.IsArgs ? CilOpCodes.Ldarga : CilOpCodes.Ldloca, sa.Index);
                break;
            case SymValue.ArrayElemAddr aea:
            {
                EmitPush(aea.Array);
                EmitPush(aea.Index);
                var elemType = ArrayElementType(KnownTypeOf(aea.Array))
                    ?? throw new LiftUnsupported("ldelema: array element type unknown");
                Emit(CilOpCodes.Ldelema, elemType.ToTypeDefOrRef());
                break;
            }
            case SymValue.HandlerLocalAddr address:
                EmitPush(address.Value);
                break;
            // A peeked value's original is still owned by the VM's own logical stack (Peek doesn't
            // remove it) — re-emitting it here (the runtime's peek+push+pop "dup" idiom) must
            // genuinely duplicate the real stack slot, or the original's later consumer starves.
            case SymValue.OnStack { Peeked: true }:
                Emit(CilOpCodes.Dup);
                break;
            case SymValue.OnStack:
            case SymValue.Void:
                break; // already on the stack, or a void result — nothing to load
            case SymValue.FnPtr fp:
                Emit(CilOpCodes.Ldftn, fp.Method);
                break;
            case SymValue.Cond cc:
                // The comparison's Call was already emitted eagerly at production time (with its
                // real arguments correctly in place then); only an outstanding negation remains.
                if (cc.Negate) { Emit(CilOpCodes.Ldc_I4, 0); Emit(CilOpCodes.Ceq); }
                break;
            case SymValue.Operand o:
                EmitConstant(o.Value);
                break;
            case SymValue.Constant c:
                EmitConstant(c.Value);
                break;
            case SymValue.ResolvedString resolved:
                EmitResolvedString(resolved);
                break;
            case SymValue.DefaultValue dv:
            {
                int temp = AllocTemp(dv.Type);
                Emit(CilOpCodes.Ldloca, new TempLocalRef(temp));
                Emit(CilOpCodes.Initobj, dv.Type.ToTypeDefOrRef());
                Emit(CilOpCodes.Ldloc, new TempLocalRef(temp));
                break;
            }
            // A Type resolved via the runtime's reflection-anchored ResolveType helper (e.g.
            // Module.ResolveType(token), the compiled form of a `typeof(X)` that survived
            // virtualization as a token lookup) being pushed/stored as a real value — same
            // `ldtoken; call GetTypeFromHandle` idiom as a tracked TypeSignature constant.
            case SymValue.Resolved { Kind: HelperRole.ResolveType, Member: ITypeDefOrRef type }:
                Emit(CilOpCodes.Ldtoken, type);
                Emit(CilOpCodes.Call, GetTypeFromHandleMarker.Instance);
                break;
            // fieldInfo.FieldHandle / type.TypeHandle: the raw ldtoken idiom (no further
            // GetXFromHandle call — unlike materialising the member itself as a live object above).
            case SymValue.RawHandle rh:
                Emit(CilOpCodes.Ldtoken, rh.Member);
                break;
            case SymValue.Unknown u:
                throw new LiftUnsupported($"cannot materialise pushed value [{u.Reason}]");
            default:
                throw new LiftUnsupported($"cannot materialise pushed value {value}");
        }
    }

    private void EmitConstant(object? v)
    {
        switch (v)
        {
            case null: Emit(CilOpCodes.Ldnull); break;
            case string s: Emit(CilOpCodes.Ldstr, s); break;
            case bool b: Emit(CilOpCodes.Ldc_I4, b ? 1 : 0); break;
            case int i: Emit(CilOpCodes.Ldc_I4, i); break;
            case uint u: Emit(CilOpCodes.Ldc_I4, unchecked((int)u)); break;
            case long l: Emit(CilOpCodes.Ldc_I8, l); break;
            case ulong ul: Emit(CilOpCodes.Ldc_I8, unchecked((long)ul)); break;
            case float f: Emit(CilOpCodes.Ldc_R4, f); break;
            case double d: Emit(CilOpCodes.Ldc_R8, d); break;
            case TypeSignature ts:
                // Materialise typeof(ts): the standard `ldtoken T; call Type.GetTypeFromHandle` idiom.
                Emit(CilOpCodes.Ldtoken, ts.ToTypeDefOrRef());
                Emit(CilOpCodes.Call, GetTypeFromHandleMarker.Instance);
                break;
            default: throw new LiftUnsupported($"cannot push constant of type {v.GetType().Name} [{v}]");
        }
    }

    private void EvalIsinst(CilInstruction cil)
    {
        var value = Pop();
        string wanted = (cil.Operand as ITypeDefOrRef)?.Name?.ToString() ?? "";
        // A Module.ResolveMember() result is only ambiguously typed until DoResolve classified it by
        // its own signature (see ClassifyMember) — an `isinst FieldInfo/MethodInfo/.../Type` cascade
        // on it (the compiled form of "which kind of member is this?") must respect that classification
        // rather than assume every isinst against a resolved member succeeds.
        if (value is SymValue.Resolved { Member: { } member } r)
        {
            bool isField = r.Kind == HelperRole.ResolveField;
            bool isMethod = r.Kind == HelperRole.ResolveMethod;
            bool isType = r.Kind == HelperRole.ResolveType;
            bool isCtor = isMethod && member is IMethodDescriptor md && md.Name?.ToString() is ".ctor" or ".cctor";
            bool matches = wanted switch
            {
                "FieldInfo" => isField,
                "MethodInfo" => isMethod && !isCtor,
                "ConstructorInfo" => isMethod && isCtor,
                "MethodBase" => isMethod,
                "Type" => isType,
                "MemberInfo" => true,
                _ => true,
            };
            _eval.Push(matches ? value : new SymValue.Operand(null));
            return;
        }
        // `isinst <T>` on a live VM value: when we've concretely tracked its CLR type (KnownType),
        // answer truthfully from that (e.g. the runtime's "which numeric type is this boxed value?"
        // isinst-Int32/isinst-Int64/… cascade). Otherwise default to false — a normal boxed program
        // value is never one of the runtime's own internal wrapper types (e.g. the by-ref-local
        // wrapper y34=), which is the common case reaching here with no tracked type at all.
        if (value is SymValue.OnStack os)
        {
            bool matches = os.KnownType is { } kt
                && cil.Operand is ITypeDefOrRef target
                && IsKnownAssignableTo(kt, target);
            _eval.Push(matches ? value : new SymValue.Operand(null));
            return;
        }
        _eval.Push(value);
    }

    private bool TryReflectionAccessor(IMethodDescriptor m)
    {
        string dt = m.DeclaringType?.Name?.ToString() ?? "";
        string n = m.Name?.ToString() ?? "";
        switch (n)
        {
            case "GetTypeFromHandle":
                // ldtoken already produced the type descriptor; pass it through.
                return true;
            case "get_ReturnType":
                // Same generic-substitution need as SigReturn (reused directly): a raw MethodSignature
                // (via SigOf) reports the UNSUBSTITUTED return type for a method on a generic-instance
                // declaring type (e.g. Dictionary<string,string>.get_Item returns `!1`, not
                // System.String) — that's meaningless outside the method's own generic context and
                // produces an unresolvable `ldtoken` if materialised as-is.
                _eval.Push(new SymValue.Operand(MemberOf(Receiver()) is IMethodDescriptor rmd ? SigReturn(rmd) : null));
                return true;
            case "get_IsStatic":
                _eval.Push(new SymValue.Operand(IsStaticMember(Receiver())));
                return true;
            case "get_FieldType":
                _eval.Push(new SymValue.Operand(FieldTypeOf(Receiver())));
                return true;
            case "get_DeclaringType" or "get_ReflectedType":
                _eval.Push(new SymValue.Unknown("declaringType"));
                return true;
            case "get_MethodHandle":
                // method.MethodHandle … .GetFunctionPointer() is the ldftn idiom.
                _eval.Push(MemberOf(Receiver()) is IMethodDescriptor md ? new SymValue.FnPtr(md) : new SymValue.Unknown());
                return true;
            case "get_FieldHandle":
                // field.FieldHandle is the reflection-based equivalent of the raw `ldtoken <field>`
                // instruction (which pushes a RuntimeFieldHandle directly, no further call needed).
                // Match by Kind (how the token was resolved), not a bare interface test: a
                // MemberReference satisfies IFieldDescriptor even when it was resolved as a method.
                _eval.Push(Receiver() is SymValue.Resolved { Kind: HelperRole.ResolveField, Member: IFieldDescriptor fd }
                    ? new SymValue.RawHandle(fd)
                    : new SymValue.Unknown("call FieldInfo.get_FieldHandle"));
                return true;
            case "get_TypeHandle":
                // type.TypeHandle: same raw-ldtoken idiom as get_FieldHandle above, for a resolved type.
                _eval.Push(Receiver() is SymValue.Resolved { Kind: HelperRole.ResolveType, Member: ITypeDefOrRef td }
                    ? new SymValue.RawHandle(td)
                    : new SymValue.Unknown("call Type.get_TypeHandle"));
                return true;
            case "GetFunctionPointer":
                return true; // pass the FnPtr marker through
            case "op_Inequality" when dt == "Type":
                { var b = Pop(); var a = Pop(); _eval.Push(new SymValue.Operand(!TypeEq(a, b))); return true; }
            case "op_Equality" when dt == "Type":
                { var b = Pop(); var a = Pop(); _eval.Push(new SymValue.Operand(TypeEq(a, b))); return true; }
        }
        return false;
    }

    private SymValue Receiver()
    {
        return HandlerLocalValue(Pop());
    }

    private static SymValue HandlerLocalValue(SymValue value) =>
        value is SymValue.HandlerLocalAddr address ? address.Value : value;

    // ---- branch resolution -------------------------------------------------

    private int ResolveBranch(SymValue cond, int taken, int fall, bool wantTrue)
    {
        // Cond branches are resolved locally at the Brtrue/Brfalse call site (see
        // ExecuteInterpreter.CondBranch.cs) before ever reaching here.
        if (cond is SymValue.Cond)
            throw new LiftUnsupported("unresolved comparison result reached generic branch resolution");
        if (TryConstBool(cond, out bool b))
            return b == wantTrue ? taken : fall;
        if (IsGuardThrowTarget(taken)) return fall;
        if (IsGuardThrowTarget(fall)) return taken;
        // Remaining execute-IL branches test the VM's value representation (byref-wrapper?, storage
        // kind, …) and reconverge with equivalent program meaning; the canonical path is fall-through.
        return fall;
    }

    private int ResolveEqBranch(SymValue b, SymValue a, int taken, int fall, bool wantEqual)
    {
        if (a is SymValue.Cond || b is SymValue.Cond)
            throw new LiftUnsupported("unresolved comparison result reached an equality branch");
        if (TryConstEq(a, b, out bool eq))
            return eq == wantEqual ? taken : fall;
        if (IsGuardThrowTarget(taken)) return fall;
        if (IsGuardThrowTarget(fall)) return taken;
        return fall;
    }

    private int ResolveRelBranch(SymValue b, SymValue a, int taken, int fall, Func<long, long, bool> op)
    {
        if (a is SymValue.Cond || b is SymValue.Cond)
            throw new LiftUnsupported("unresolved comparison result reached a relational branch");
        if (TryLong(a, out long la) && TryLong(b, out long lb))
            return op(la, lb) ? taken : fall;
        if (IsGuardThrowTarget(taken)) return fall;
        if (IsGuardThrowTarget(fall)) return taken;
        return fall;
    }

    /// <summary>
    /// True if control from <paramref name="index"/> runs straight into a <c>throw</c> before any
    /// return — i.e. a VM runtime guard (null/type check) that has no counterpart in the original CIL.
    /// </summary>
    private bool IsGuardThrowTarget(int index)
    {
        for (int i = index, steps = 0; i >= 0 && i < _body.Count && steps < 30; i++, steps++)
        {
            switch (_body[i].OpCode.Code)
            {
                case CilCode.Throw: return true;
                case CilCode.Ret: return false;
            }
        }
        return false;
    }

    // ---- symbolic-value evaluation ----------------------------------------

    private static bool AsBool(SymValue v) => TryConstBool(v, out bool b) && b;
    private int AsInt(SymValue v) => TryInt(v, out int i) ? i : throw new LiftUnsupported($"expected an integer, got {v}");

    private static bool TryInt(SymValue v, out int result)
    {
        if (v is SymValue.Operand { Value: { } o } && IsIntLike(o)) { result = Convert.ToInt32(o); return true; }
        result = 0;
        return false;
    }

    private static bool TryConstBool(SymValue v, out bool result)
    {
        switch (v)
        {
            case SymValue.Operand { Value: bool b }: result = b; return true;
            case SymValue.Operand { Value: null }: result = false; return true;
            case SymValue.Constant { Value: null }: result = false; return true;
            case SymValue.Operand { Value: { } o } when IsIntLike(o): result = Convert.ToInt64(o) != 0; return true;
            case SymValue.Operand: result = true; return true;               // non-null reference (string, type…)
            case SymValue.ResolvedString: result = true; return true;
            case SymValue.Resolved r: result = r.Member is not null; return true;
            // A value taken off the VM eval stack is a live (non-null) boxed wrapper: null-conditional
            // and presence checks in the handler (`hn != null`) take the has-value path.
            case SymValue.OnStack: result = true; return true;
            default: result = false; return false;
        }
    }

    private bool TryConstEq(SymValue a, SymValue b, out bool eq)
    {
        // type == type (after GetTypeFromHandle) and null comparisons are the cases handlers branch on.
        if (IsTypeVal(a) || IsTypeVal(b)) { eq = TypeEq(a, b); return true; }
        if (TryLiteralValue(a, out object? av) && TryLiteralValue(b, out object? bv))
        {
            if (av is null || bv is null) { eq = av is null && bv is null; return true; }
            if (IsIntLike(av) && IsIntLike(bv)) { eq = Convert.ToInt64(av) == Convert.ToInt64(bv); return true; }
        }
        eq = false;
        return false;
    }

    private static bool IsTypeVal(SymValue v) =>
        v is SymValue.Operand { Value: TypeSignature or ITypeDefOrRef };

    private static bool IsNullLiteral(SymValue value) => value is
        SymValue.Operand { Value: null } or SymValue.Constant { Value: null };

    private static bool TryLiteralValue(SymValue value, out object? literal)
    {
        switch (value)
        {
            case SymValue.Operand operand: literal = operand.Value; return true;
            case SymValue.Constant constant: literal = constant.Value; return true;
            case SymValue.ResolvedString resolved: literal = resolved.Value; return true;
            default: literal = null; return false;
        }
    }

    private static bool TypeEq(SymValue a, SymValue b) => TypeName(a) is { } x && TypeName(b) is { } y && x == y;

    private static string? TypeName(SymValue v) => v switch
    {
        SymValue.Operand { Value: TypeSignature ts } => ts.FullName,
        SymValue.Operand { Value: ITypeDefOrRef t } => t.FullName,
        _ => null,
    };

    // ---- resolved-member helpers ------------------------------------------

    private IMetadataMember? LookupToken(object token) =>
        _module.TryLookupMember(new MetadataToken(Convert.ToUInt32(token)), out var m) ? m : null;

    private static IMetadataMember? MemberOf(SymValue v) => v is SymValue.Resolved r ? r.Member : null;

    private static MethodSignature? SigOf(SymValue v) => MemberOf(v) switch
    {
        MethodDefinition md => md.Signature,
        MemberReference { Signature: MethodSignature ms } => ms,
        _ => null,
    };

    // Note: a MemberReference satisfies BOTH IMethodDescriptor and IFieldDescriptor, so we must
    // decide field-vs-method by how the token was resolved, not by an interface test.
    private bool IsStaticMember(SymValue v) =>
        v is SymValue.Resolved { Kind: HelperRole.ResolveField, Member: IFieldDescriptor f }
            ? FieldIsStatic(f)
            : !(SigOf(v)?.HasThis ?? true);

    /// <summary>Static-ness of a field, preferring the definition to avoid failing on odd references.</summary>
    private bool FieldIsStatic(IFieldDescriptor f)
    {
        if (f is FieldDefinition fd) return fd.IsStatic;
        try { return f.Resolve(_ctx)?.IsStatic ?? throw new LiftUnsupported("unresolved field"); }
        catch (LiftUnsupported) { throw; }
        catch { throw new LiftUnsupported("cannot decide field static-ness"); }
    }

    private object? FieldTypeOf(SymValue v) => MemberOf(v) switch
    {
        FieldDefinition fd => fd.Signature?.FieldType,
        IFieldDescriptor f => TryFieldSig(f),
        _ => null,
    };

    private object? TryFieldSig(IFieldDescriptor f) { try { return f.Resolve(_ctx)?.Signature?.FieldType; } catch { return null; } }

    // ---- descriptor helpers -----------------------------------------------

    private MethodDefinition? ResolveM(IMethodDescriptor m) { try { return m.Resolve(_ctx); } catch { return null; } }
    private static bool Same(MethodDefinition? a, MethodDefinition? b) => a is not null && ReferenceEquals(a, b);
    private static int ParamCount(IMethodDescriptor m) => m.Signature?.ParameterTypes.Count ?? 0;
    private static bool HasThis(IMethodDescriptor m) => m.Signature?.HasThis ?? false;
    // For a generic method instantiation (MethodSpecification), IMethodDescriptor.Signature is the
    // UNDERLYING generic method DEFINITION's own signature — its ReturnType may be (or contain) the
    // method's own unsubstituted generic parameter (`!!0`), e.g. Enumerable.ToArray<Byte>(...)'s
    // declared return type is literally `!!0[]`, not `System.Byte[]`. `!!0` outside the generic
    // method's own body resolves to nothing, so a narrowing `castclass` built from it collapses to
    // Object at verification time. InstantiateGenericTypes substitutes both the declaring type's and
    // the method's own generic arguments (a no-op for a non-generic method/type), giving the real
    // concrete return type every caller of SigReturn actually needs.
    private static TypeSignature? SigReturn(IMethodDescriptor m) =>
        m.Signature?.ReturnType?.InstantiateGenericTypes(GenericContext.FromMethod(m));
    private static bool LastParamIsBool(IMethodDescriptor m) =>
        m.Signature is { } s && s.ParameterTypes.Count > 0 && s.ParameterTypes[^1].IsTypeOf("System", "Boolean");

    private static bool IsIntLike(object o) =>
        o is byte or sbyte or short or ushort or int or uint or long or ulong or bool;
}
