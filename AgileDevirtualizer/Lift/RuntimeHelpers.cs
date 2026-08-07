using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Classifies the reflection-anchored effect of any runtime method or BCL call. A thin runtime
/// wrapper (e.g. one that only calls <c>Module.ResolveMethod</c> or <c>MethodBase.Invoke</c>) is
/// recognized by the single BCL anchor it forwards to, so the lifter can treat a call to that
/// wrapper as, say, "resolve a method token" or "invoke" without knowing its randomized name.
/// Direct BCL calls the lifter meets inline are classified by the same rules.
/// </summary>
internal sealed class RuntimeHelpers
{
    private readonly RuntimeContext? _ctx;
    private readonly Dictionary<MethodDefinition, HelperRole> _cache = new();

    private RuntimeHelpers(RuntimeContext? ctx) => _ctx = ctx;

    public static RuntimeHelpers Build(RuntimeModel runtime) => new(runtime.Module.RuntimeContext);

    /// <summary>Role of a call target: BCL anchors directly, runtime wrappers by what they forward to.</summary>
    public HelperRole RoleOf(IMethodDescriptor? method)
    {
        if (method is null)
            return HelperRole.None;

        var direct = AnchorRole(method);
        if (direct != HelperRole.None)
            return direct;

        var def = Resolve(method);
        return def is not null ? RoleOfDefinition(def) : HelperRole.None;
    }

    private HelperRole RoleOfDefinition(MethodDefinition def)
    {
        if (_cache.TryGetValue(def, out var cached))
            return cached;

        // A wrapper forwards *directly* to its BCL anchor, so we only look at this method's own
        // call sites — no transitive chasing (that would tag every method reaching any anchor).
        var role = HelperRole.None;
        if (def.CilMethodBody is { } body)
        {
            foreach (var instr in body.Instructions)
            {
                if (instr.OpCode.Code is not (CilCode.Call or CilCode.Callvirt))
                    continue;
                if (instr.Operand is IMethodDescriptor callee && AnchorRole(callee) is var r and not HelperRole.None)
                    { role = r; break; }
                if (instr.Operand is IMethodDescriptor coercionAnchor
                    && IsEnumToObject(coercionAnchor)
                    && IsByRefCoercionSignature(def.Signature))
                    { role = HelperRole.CoerceByRef; break; }
            }
        }
        return _cache[def] = role;
    }

    /// <summary>Direct match against the BCL reflection surface the VM is built on.</summary>
    private static HelperRole AnchorRole(IMethodDescriptor m)
    {
        string type = m.DeclaringType?.Name?.ToString() ?? "";
        string ns = m.DeclaringType?.Namespace?.ToString() ?? "";
        string name = m.Name?.ToString() ?? "";

        if (ns == "System.Reflection")
        {
            switch (type)
            {
                case "Module" when name == "ResolveMethod": return HelperRole.ResolveMethod;
                case "Module" when name == "ResolveField": return HelperRole.ResolveField;
                case "Module" when name == "ResolveType": return HelperRole.ResolveType;
                case "Module" when name == "ResolveString": return HelperRole.ResolveString;
                case "Module" when name == "ResolveMember": return HelperRole.ResolveMember;
                case "ConstructorInfo" when name == "Invoke": return HelperRole.NewObj;
                case "MethodBase" when name == "Invoke": return HelperRole.Invoke;
                case "MethodInfo" when name == "Invoke": return HelperRole.Invoke;
                case "FieldInfo" when name == "SetValue": return HelperRole.FieldSet;
                case "FieldInfo" when name == "GetValue": return HelperRole.FieldGet;
            }
        }
        return HelperRole.None;
    }

    private static bool IsEnumToObject(IMethodDescriptor method) =>
        method.DeclaringType?.IsTypeOf("System", "Enum") == true
        && method.Name?.ToString() == "ToObject";

    private static bool IsByRefCoercionSignature(MethodSignature? signature) =>
        signature is { HasThis: false, ParameterTypes.Count: 2 }
        && signature.ReturnType.IsTypeOf("System", "Void")
        && signature.ParameterTypes[0] is ByReferenceTypeSignature byReference
        && byReference.BaseType.IsTypeOf("System", "Object")
        && signature.ParameterTypes[1].IsTypeOf("System", "Type");

    private MethodDefinition? Resolve(IMethodDescriptor m)
    {
        try { return m.Resolve(_ctx); } catch { return null; }
    }
}
