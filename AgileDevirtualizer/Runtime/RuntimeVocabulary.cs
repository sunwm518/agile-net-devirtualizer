using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Runtime;

/// <summary>
/// Identifies, purely by structure, the small set of VM "primitive" methods every handler is
/// written in terms of: the evaluation stack (push/pop/peek), the context accessors for
/// locals/arguments/instruction-pointer/return value, and the boxed-value type. Names are
/// randomized per build, so each role is recovered from shape and usage, never from a name.
///
/// This is the vocabulary the execute-method lifter interprets against.
/// </summary>
internal sealed class RuntimeVocabulary
{
    public required TypeDefinition ContextType { get; init; }
    public required TypeDefinition StackType { get; init; }
    public required TypeDefinition ValueType { get; init; }   // the boxed-value wrapper (hn4=)

    // Stack (on StackType)
    public required MethodDefinition Pop { get; init; }
    public MethodDefinition? Peek { get; init; }
    public required IReadOnlyList<MethodDefinition> Push { get; init; }

    // Context accessors (on ContextType)
    public required MethodDefinition GetStack { get; init; }
    public required MethodDefinition GetLocals { get; init; }
    public required MethodDefinition GetArgs { get; init; }
    public MethodDefinition? SetLocal { get; init; }
    public required MethodDefinition GetIp { get; init; }
    public required MethodDefinition SetIp { get; init; }
    public MethodDefinition? SetReturn { get; init; }
    public required RuntimeContext? ResolveContext { get; init; }

    public bool IsPush(IMethodDescriptor? m)
    {
        try { return m?.Resolve(ResolveContext) is { } d && Push.Contains(d); }
        catch { return false; }
    }

    public static RuntimeVocabulary Build(RuntimeModel runtime)
    {
        var ctx = runtime.ContextType;
        var context = runtime.Module.RuntimeContext;
        TypeDefinition? Res(ITypeDescriptor? t) { try { return t?.Resolve(context); } catch { return null; } }

        var getters = ctx.Methods.Where(m => m is { IsStatic: false } && m.Signature is { } s
            && s.ParameterTypes.Count == 0 && !IsVoid(s.ReturnType) && m.CilMethodBody is not null).ToList();

        // The boxed-value wrapper (hn4=) is the element type of the locals/argument arrays: the
        // parameterless ctx getters that return value[]. Same-module, always resolvable.
        var arrayGetters = getters
            .Where(g => g.Signature!.ReturnType is SzArrayTypeSignature)
            .Select(g => (getter: g, elem: Res(((SzArrayTypeSignature)g.Signature!.ReturnType).BaseType)))
            .Where(x => x.elem is not null)
            .ToList();
        var valueType = arrayGetters
            .GroupBy(x => x.elem!)
            .MaxBy(grp => grp.Count())?.Key
            ?? throw new InvalidOperationException("Could not identify the VM boxed-value type (no value[] accessors).");
        var valueArrayGetters = arrayGetters.Where(x => x.elem == valueType).Select(x => x.getter).ToList();

        // The evaluation stack: a ctx getter returning a type that has a parameterless pop
        // (returns the value type) and at least one void push.
        MethodDefinition? getStack = null, pop = null, peek = null;
        TypeDefinition? stackType = null;
        var pushes = new List<MethodDefinition>();
        foreach (var g in getters)
        {
            if (Res(g.Signature!.ReturnType) is not { } rt || rt == valueType)
                continue;
            // The parameterless value-returning methods are pop (mutates the stack — has a stfld)
            // and peek (pure read). Distinguish by mutation rather than by an arbitrary order.
            var valueReturners = rt.Methods.Where(m => m is { IsStatic: false } && m.Signature is { } s
                && s.ParameterTypes.Count == 0 && Res(s.ReturnType) == valueType && m.CilMethodBody is { }).ToList();
            var popCand = valueReturners.FirstOrDefault(m => Mutates(m)) ?? valueReturners.FirstOrDefault();
            // Push takes a single value (the wrapper or object, optionally plus a storage-kind enum),
            // never an array — that excludes copy/ctor helpers.
            var pushCand = rt.Methods.Where(m => m is { IsStatic: false, IsConstructor: false }
                && (m.Name?.ToString().Contains('.') != true)
                && m.Signature is { } s && IsVoid(s.ReturnType) && m.CilMethodBody is { }
                && s.ParameterTypes.Count is 1 or 2
                && IsSingleValueParam(s.ParameterTypes[0], valueType)).ToList();
            if (popCand is null || pushCand.Count == 0)
                continue;
            getStack = g; stackType = rt; pop = popCand; pushes = pushCand;
            peek = valueReturners.FirstOrDefault(m => m != pop && !Mutates(m));
            break;
        }
        if (getStack is null || stackType is null || pop is null)
            throw new InvalidOperationException("Could not identify the VM evaluation stack primitives.");

        // SetLocal writes ctx.<getLocals>()[i] = value; recover which array getter it indexes to
        // tell locals from arguments.
        MethodDefinition? setLocal = null, getLocals = null;
        foreach (var m in ctx.Methods)
        {
            if (m is { IsStatic: false } && m.Signature is { } s && IsVoid(s.ReturnType)
                && s.ParameterTypes.Count == 2 && IsIntLike(s.ParameterTypes[0])
                && Res(s.ParameterTypes[1]) == valueType && m.CilMethodBody is { } body)
            {
                MethodDefinition? ResM(IMethodDescriptor? d) { try { return d?.Resolve(context); } catch { return null; } }
                var used = body.Instructions
                    .Where(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt)
                    .Select(i => ResM(i.Operand as IMethodDescriptor))
                    .FirstOrDefault(md => md is not null && valueArrayGetters.Contains(md));
                if (used is not null) { setLocal = m; getLocals = used; break; }
            }
        }
        getLocals ??= valueArrayGetters.FirstOrDefault();
        var getArgs = valueArrayGetters.FirstOrDefault(g => g != getLocals) ?? getLocals;
        if (getLocals is null || getArgs is null)
            throw new InvalidOperationException("Could not identify the VM locals/arguments accessors.");

        // IP getter/setter: void(int) setter storing field F, and parameterless int getter loading F.
        MethodDefinition? setIp = null, getIp = null;
        foreach (var setter in ctx.Methods.Where(m => m is { IsStatic: false } && m.Signature is { } s
                     && IsVoid(s.ReturnType) && s.ParameterTypes.Count == 1 && IsInt32(s.ParameterTypes[0])))
        {
            var field = SimpleSetterField(setter, context);
            if (field is null) continue;
            var getter = ctx.Methods.FirstOrDefault(m => m is { IsStatic: false } && m.Signature is { } s
                && s.ParameterTypes.Count == 0 && IsInt32(s.ReturnType) && SimpleGetterField(m, context) == field);
            if (getter is not null) { setIp = setter; getIp = getter; break; }
        }
        if (setIp is null || getIp is null)
            throw new InvalidOperationException("Could not identify the VM instruction-pointer accessors.");

        var setReturn = ctx.Methods.FirstOrDefault(m => m is { IsStatic: false } && m.Signature is { } s
            && IsVoid(s.ReturnType) && s.ParameterTypes.Count == 1 && IsObject(s.ParameterTypes[0])
            && SimpleSetterField(m, context) is not null);

        return new RuntimeVocabulary
        {
            ContextType = ctx, StackType = stackType, ValueType = valueType,
            Pop = pop, Peek = peek, Push = pushes,
            GetStack = getStack, GetLocals = getLocals, GetArgs = getArgs, SetLocal = setLocal,
            GetIp = getIp, SetIp = setIp, SetReturn = setReturn, ResolveContext = context,
        };
    }

    private static FieldDefinition? SimpleSetterField(MethodDefinition m, RuntimeContext ctx)
    {
        if (m.CilMethodBody is not { } body) return null;
        foreach (var i in body.Instructions)
            if (i.OpCode.Code == CilCode.Stfld && i.Operand is IFieldDescriptor f)
                { try { return f.Resolve(ctx); } catch { return null; } }
        return null;
    }

    private static FieldDefinition? SimpleGetterField(MethodDefinition m, RuntimeContext ctx)
    {
        if (m.CilMethodBody is not { } body) return null;
        foreach (var i in body.Instructions)
            if (i.OpCode.Code == CilCode.Ldfld && i.Operand is IFieldDescriptor f)
                { try { return f.Resolve(ctx); } catch { return null; } }
        return null;
    }

    private static bool Mutates(MethodDefinition m) =>
        m.CilMethodBody?.Instructions.Any(i => i.OpCode.Code == CilCode.Stfld) ?? false;

    /// <summary>A single pushed value: the boxed-value wrapper or System.Object (not an array).</summary>
    private static bool IsSingleValueParam(TypeSignature? t, TypeDefinition valueType)
        => t is not null && t is not SzArrayTypeSignature
           && (t.IsTypeOf("System", "Object") || SameType(t, valueType));

    private static bool SameType(TypeSignature? t, TypeDefinition td)
        => t is not null && t.Name == td.Name && t.Namespace == td.Namespace;

    private static bool IsVoid(TypeSignature? t) => t?.IsTypeOf("System", "Void") ?? false;
    private static bool IsInt32(TypeSignature? t) => t?.IsTypeOf("System", "Int32") ?? false;
    private static bool IsIntLike(TypeSignature? t) => t is not null && (t.IsTypeOf("System", "Int32") || t.IsTypeOf("System", "UInt32"));
    private static bool IsObject(TypeSignature? t) => t?.IsTypeOf("System", "Object") ?? false;
}
