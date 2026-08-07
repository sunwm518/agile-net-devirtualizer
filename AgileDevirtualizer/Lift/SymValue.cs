using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// A symbolic value tracked while interpreting a handler's execute-method IL. Values are either VM
/// infrastructure references (the context, the eval stack, the locals/args arrays), operand data
/// pulled from the decoded instruction, a "loadable" source that becomes a CIL load when the VM
/// pushes it, or a marker that a real value already sits on the reconstructed CIL eval stack.
/// </summary>
internal abstract record SymValue
{
    /// <summary>The execute-method's <c>ctx</c> parameter.</summary>
    public sealed record Ctx : SymValue;

    /// <summary>Result of <c>ctx.getStack()</c>.</summary>
    public sealed record StackRef : SymValue;

    /// <summary>Result of <c>ctx.getLocals()</c> / <c>ctx.getArgs()</c>.</summary>
    public sealed record SlotArray(bool IsArgs) : SymValue;

    /// <summary>The protected module (….ManifestModule), used as the token-resolution scope.</summary>
    public sealed record ModuleRef : SymValue;

    /// <summary>A raw operand value from the decoded instruction (constant, token, index, array…).</summary>
    public sealed record Operand(object? Value) : SymValue;

    /// <summary>A pending local/argument read: becomes <c>ldloc</c>/<c>ldarg</c> when pushed.</summary>
    public sealed record SlotRead(bool IsArgs, int Index) : SymValue;

    /// <summary>
    /// The address of a VM local/argument slot — the runtime's "by-ref" wrapper, constructed as
    /// <c>new Wrapper(ctx.getLocals()/getArgs(), index)</c> (detected structurally: a newobj whose
    /// first argument is a <see cref="SlotArray"/>). Becomes <c>ldloca</c>/<c>ldarga</c> when pushed,
    /// letting VM locals/args be passed by reference to a real call (out/ref parameters).
    /// </summary>
    public sealed record SlotAddr(bool IsArgs, int Index) : SymValue;

    /// <summary>
    /// The address of an arbitrary array element — the SAME by-ref wrapper as <see cref="SlotAddr"/>
    /// also supports constructing from a genuine array value instead of a VM slot array (detected
    /// structurally: a newobj whose OWN declared first parameter type is <c>System.Array</c>, rather
    /// than by the argument's runtime shape). Becomes <c>ldelema &lt;elementType&gt;</c> when pushed.
    /// </summary>
    public sealed record ArrayElemAddr(SymValue Array, SymValue Index) : SymValue;

    /// <summary>
    /// Address of a local belonging to the handler's own execute method. Keeping the index as well
    /// as its current symbolic value lets a structurally recognized <c>ref object</c> coercion helper
    /// update that local's CLR type, while ordinary read-only address consumers can still use
    /// <see cref="Value"/> exactly as they used the former plain-local model.
    /// </summary>
    public sealed record HandlerLocalAddr(int Index, SymValue Value) : SymValue;

    /// <summary>A pending constant push: becomes <c>ldc</c>/<c>ldstr</c>/<c>ldnull</c> when pushed.</summary>
    public sealed record Constant(object? Value) : SymValue;

    /// <summary>
    /// A user string resolved from VM bytecode together with its original raw token. Agile accepts
    /// user-string offsets larger than the 24 bits available to a native CIL <c>ldstr</c> token;
    /// retaining the raw value lets emission avoid producing an invalid 0x71... token.
    /// </summary>
    public sealed record ResolvedString(string Value, uint RawToken) : SymValue;

    /// <summary>
    /// The VM wrapper produced for <c>default(T)</c> by its Activator-backed value factory. It stays
    /// symbolic until a by-ref slot setter turns it into <c>initobj T</c>, or until it must be
    /// materialised as a genuine value.
    /// </summary>
    public sealed record DefaultValue(TypeSignature Type) : SymValue;

    /// <summary>A metadata member resolved from a token (method/field/type/string).</summary>
    public sealed record Resolved(HelperRole Kind, IMetadataMember? Member) : SymValue;

    /// <summary>
    /// A raw metadata-token handle (<c>RuntimeFieldHandle</c> / <c>RuntimeTypeHandle</c>) obtained via
    /// the reflection <c>FieldHandle</c>/<c>TypeHandle</c> property on an already-resolved member —
    /// materialises as a bare <c>ldtoken &lt;member&gt;</c>. This differs from materialising the
    /// member ITSELF as a live Type/MemberInfo object (<see cref="Resolved"/> pushed directly), which
    /// additionally needs a <c>GetTypeFromHandle</c>-style call after the <c>ldtoken</c>.
    /// </summary>
    public sealed record RawHandle(IMetadataMember Member) : SymValue;

    /// <summary>
    /// A value that already sits on the reconstructed CIL eval stack (a producing op ran).
    /// <paramref name="KnownType"/> is the value's CLR type WHEN we can derive it (from a VM local's
    /// declared type, a resolved field's type, a call's return type, or a prior conversion) — used
    /// to concretely resolve <c>value.GetType() == typeof(X)</c> checks the runtime uses to dispatch
    /// between numeric-conversion overloads. Null when genuinely unknown (never guessed).
    /// <paramref name="Peeked"/> marks a value obtained via the VM's non-removing top-of-stack read
    /// (<c>ctx.Peek()</c>) rather than <c>ctx.Pop()</c> — the VM's own logical stack still owns the
    /// original, so re-emitting a peeked value (e.g. the runtime's peek+push+pop "dup" idiom) must
    /// materialise a genuine <c>dup</c> rather than the usual no-op (which is only correct when the
    /// value was popped, i.e. already relinquished by the VM stack and safe to hand back untouched).
    /// <paramref name="ManagedPointer"/> distinguishes an address produced by ldloca/ldarga/ldelema
    /// from a raw value of the same <paramref name="KnownType"/>. This prevents address receivers from
    /// triggering ordinary value boxing and enables constrained virtual dispatch where structurally safe.
    /// <paramref name="KnownNull"/> preserves an actual <c>ldnull</c> after it travels through the VM
    /// evaluation stack; a missing type alone is not sufficient evidence that an arbitrary value is null.
    /// </summary>
    public sealed record OnStack(TypeSignature? KnownType = null, bool Peeked = false,
                                 bool ManagedPointer = false, bool KnownNull = false) : SymValue;

    /// <summary>The (absent) result of a void call: materialising it emits nothing.</summary>
    public sealed record Void : SymValue;

    /// <summary>
    /// The exception currently being dispatched by the VM context. Agile's rethrow handler obtains
    /// this value from a parameterless context accessor and immediately throws it; native CIL must
    /// recover that operation as <c>rethrow</c>, not as <c>throw</c> of a newly loaded exception.
    /// </summary>
    public sealed record CurrentException : SymValue;

    /// <summary>The instruction pointer plus a constant offset — <c>ctx.getIp() + Offset</c>.</summary>
    public sealed record Ip(int Offset) : SymValue;

    /// <summary>
    /// The boolean result of a VM comparison primitive, already emitted eagerly as a real
    /// <c>Call</c> to the exact runtime method that computes it (rather than hand-rolling
    /// ceq/clt/cgt) — so every relation (Falsy/Ne/Le/Ge included), and any type-coercion the helper
    /// does, is handled uniformly and exactly as the runtime would, with all of its real arguments
    /// correctly in place at the point they were actually pushed. This value just marks "there is a
    /// genuine, runtime-determined bool sitting on the stack right now."
    /// <paramref name="Negate"/> flips the sense (via a trailing <c>ceq 0</c>) when a consuming site
    /// needs the opposite of what was produced (e.g. a ternary's "false" arm matched the identity,
    /// so its "true" arm needs the negation).
    /// </summary>
    public sealed record Cond(Relation Rel, bool Negate = false) : SymValue;

    /// <summary>A method function pointer (method.MethodHandle.GetFunctionPointer()) — becomes ldftn.</summary>
    public sealed record FnPtr(IMethodDescriptor Method) : SymValue;

    /// <summary>A jump table (decoded int deltas) indexed by a stack value, plus an IP base — becomes switch.</summary>
    public sealed record SwitchTable(int[] Deltas, int Base) : SymValue;

    /// <summary>Anything we do not model; safe as long as it is never asked to become CIL. Reason aids diagnostics.</summary>
    public sealed record Unknown(string Reason = "") : SymValue;
}
