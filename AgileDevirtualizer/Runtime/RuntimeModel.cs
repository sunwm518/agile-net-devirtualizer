using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Runtime;

/// <summary>
/// Everything we learn about one VM handler class, derived purely from the runtime DLL.
/// Nothing here is keyed on the (randomized) type/method names.
/// </summary>
internal sealed class HandlerInfo
{
    public required ushort Opcode;
    public required TypeDefinition Type;

    /// <summary>Override of the base <c>void f(BinaryReader)</c> slot — decodes operands.</summary>
    public MethodDefinition? ReadMethod;

    /// <summary>Override of the base <c>void f(ctx)</c> slot — the execution semantics.</summary>
    public MethodDefinition? ExecuteMethod;

    public override string ToString() =>
        $"op={Opcode} {Type.Name} read={ReadMethod?.Name} exec={ExecuteMethod?.Name}";
}

/// <summary>
/// Loads an <c>AgileDotNet.VMRuntime.dll</c> and exposes its VM as data: the opcode→handler
/// map (from the registry's static constructor) and, per handler, the read/execute methods.
/// This is the single source of truth the rest of the pipeline is derived from.
/// </summary>
internal sealed class RuntimeModel
{
    public ModuleDefinition Module { get; }
    public TypeDefinition HandlerBase { get; }
    public TypeDefinition ContextType { get; }
    public MethodDefinition AbstractReadSlot { get; }
    public MethodDefinition AbstractExecuteSlot { get; }

    /// <summary>Handlers indexed by VM opcode (registration order).</summary>
    public IReadOnlyList<HandlerInfo> Handlers { get; }

    private RuntimeModel(ModuleDefinition module, TypeDefinition handlerBase, TypeDefinition ctx,
                         MethodDefinition readSlot, MethodDefinition execSlot, List<HandlerInfo> handlers)
    {
        Module = module;
        HandlerBase = handlerBase;
        ContextType = ctx;
        AbstractReadSlot = readSlot;
        AbstractExecuteSlot = execSlot;
        Handlers = handlers;
    }

    public HandlerInfo this[ushort opcode] => Handlers[opcode];

    public static RuntimeModel Load(string runtimeDllPath)
    {
        var module = ModuleDefinition.FromFile(runtimeDllPath);

        // The opcode registry is a static ctor that registers handler types in order via
        // `ldtoken <T>`. We identify the *right* one by validating that the registered types
        // share a common base which exposes the two abstract handler slots — a void f(BinaryReader)
        // (decode operands) and a void f(ctx) (execute). This works whether the VM has 11 group
        // handlers (classic build) or 574 unrolled handlers (modern build), with no magic counts.
        var found = FindHandlerRegistry(module)
            ?? throw new InvalidOperationException(
                "Could not locate the VM opcode registry (no static ctor registering a handler-base hierarchy).");
        var (handlerTypes, handlerBase, readSlot, execSlot, ctxType) = found;

        // Bind each handler's two overrides by signature (names are randomized per build).
        var handlers = new List<HandlerInfo>(handlerTypes.Count);
        for (int op = 0; op < handlerTypes.Count; op++)
        {
            var type = handlerTypes[op];
            handlers.Add(new HandlerInfo
            {
                Opcode = (ushort)op,
                Type = type,
                ReadMethod = FindOverride(type, readSlot, execSlot, ctxType, wantReader: true),
                ExecuteMethod = FindOverride(type, readSlot, execSlot, ctxType, wantReader: false),
            });
        }

        return new RuntimeModel(module, handlerBase, ctxType, readSlot, execSlot, handlers);
    }

    private readonly record struct RegistryMatch(
        List<TypeDefinition> Handlers, TypeDefinition Base,
        MethodDefinition ReadSlot, MethodDefinition ExecSlot, TypeDefinition Ctx);

    /// <summary>
    /// Scans every static constructor for an ordered run of <c>ldtoken &lt;type&gt;</c>, and keeps
    /// the one whose registered types resolve to a common base that looks like the VM handler base
    /// (has the read + execute abstract slots). Returns the handler types in registration (= opcode)
    /// order together with the derived base/slots/context.
    /// </summary>
    private static RegistryMatch? FindHandlerRegistry(ModuleDefinition module)
    {
        RegistryMatch? best = null;

        foreach (var type in module.GetAllTypes())
        {
            if (type.GetStaticConstructor()?.CilMethodBody is not { } body)
                continue;

            var ldtokenTypes = new List<TypeDefinition>();
            foreach (var instr in body.Instructions)
            {
                if (instr.OpCode.Code == CilCode.Ldtoken
                    && instr.Operand is ITypeDefOrRef tref && tref.Resolve(null) is { } td)
                    ldtokenTypes.Add(td);
            }
            if (ldtokenTypes.Count < 2)
                continue;

            // The handler base is the common base of the registered types. Restrict to the run
            // that actually derives from it (ignore incidental ldtokens), preserving order.
            var commonBase = ldtokenTypes
                .Select(t => t.BaseType?.Resolve(null))
                .Where(b => b is not null)
                .GroupBy(b => b!)
                .MaxBy(g => g.Count())?.Key;
            if (commonBase is null || !TryGetHandlerSlots(commonBase, out var readSlot, out var execSlot, out var ctx))
                continue;

            var handlers = ldtokenTypes.Where(t => t.BaseType?.Resolve(null) == commonBase).ToList();
            if (best is null || handlers.Count > best.Value.Handlers.Count)
                best = new RegistryMatch(handlers, commonBase, readSlot!, execSlot!, ctx!);
        }

        return best;
    }

    /// <summary>
    /// True if <paramref name="baseType"/> declares the VM handler contract: an abstract
    /// <c>void f(BinaryReader)</c> (decode) and an abstract <c>void f(ctx)</c> (execute).
    /// </summary>
    private static bool TryGetHandlerSlots(TypeDefinition baseType,
        out MethodDefinition? readSlot, out MethodDefinition? execSlot, out TypeDefinition? ctx)
    {
        readSlot = execSlot = null;
        ctx = null;
        var abstractSlots = baseType.Methods
            .Where(m => m.IsAbstract && m.Signature is { } s && s.ParameterTypes.Count == 1
                        && (s.ReturnType?.IsTypeOf("System", "Void") ?? false))
            .ToList();
        readSlot = abstractSlots.FirstOrDefault(m => IsBinaryReader(m.Signature!.ParameterTypes[0]));
        execSlot = abstractSlots.FirstOrDefault(m => !IsBinaryReader(m.Signature!.ParameterTypes[0]));
        if (readSlot is null || execSlot is null)
            return false;
        ctx = execSlot.Signature!.ParameterTypes[0].Resolve(null);
        return ctx is not null;
    }

    /// <summary>
    /// Finds the handler method overriding the requested base slot. Prefers explicit MethodImpl
    /// bindings (Agile renames overrides so they cannot bind by name); falls back to a unique
    /// signature match (HasThis, one param of the expected type, returns void).
    /// </summary>
    private static MethodDefinition? FindOverride(TypeDefinition type, MethodDefinition readSlot,
                                                  MethodDefinition execSlot, TypeDefinition ctxType, bool wantReader)
    {
        var wantedSlot = wantReader ? readSlot : execSlot;

        foreach (var impl in type.MethodImplementations)
        {
            if (impl.Declaration?.Resolve(null) == wantedSlot && impl.Body?.Resolve(null) is { } body)
                return body;
        }

        return type.Methods.FirstOrDefault(m =>
            m.CilMethodBody != null
            && m.Signature is { } sig && sig.HasThis
            && sig.ParameterTypes.Count == 1
            && (sig.ReturnType?.IsTypeOf("System", "Void") ?? false)
            && (wantReader ? IsBinaryReader(sig.ParameterTypes[0])
                           : sig.ParameterTypes[0].Resolve(null) == ctxType));
    }

    private static bool IsBinaryReader(TypeSignature? sig) => sig?.IsTypeOf("System.IO", "BinaryReader") ?? false;
}
