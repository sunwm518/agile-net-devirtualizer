using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Assembles a real <see cref="CilMethodBody"/> from a decoded method's per-instruction lifted CIL.
/// Each VM instruction gets a start label so branch/switch operands (VM-instruction indices) resolve
/// to real CIL labels; locals and exception handlers are rebuilt from the decoded method.
/// </summary>
internal static class CilBuilder
{
    public static CilMethodBody Build(ModuleDefinition module, ModuleDefinition runtimeModule,
                                      MethodDefinition target, DecodedMethod decoded,
                                      IReadOnlyList<List<LiftedOp>> lifted, IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var importer = module.DefaultImporter;
        var body = new CilMethodBody { InitializeLocals = decoded.Locals.Count > 0 || tempLocalTypes.Count > 0 };

        var locals = new CilLocalVariable[decoded.Locals.Count];
        for (int i = 0; i < locals.Length; i++)
        {
            locals[i] = new CilLocalVariable(importer.ImportTypeSignature(decoded.Locals[i]));
            body.LocalVariables.Add(locals[i]);
        }

        // Scratch locals ExecuteInterpreter.EmitArgsBoxed reserved to stash arguments while
        // reordering around a `box` — appended after the VM's own declared locals, addressed via
        // TempLocalRef rather than a plain VM-local index.
        var temps = new CilLocalVariable[tempLocalTypes.Count];
        for (int i = 0; i < temps.Length; i++)
        {
            temps[i] = new CilLocalVariable(importer.ImportTypeSignature(tempLocalTypes[i]));
            body.LocalVariables.Add(temps[i]);
        }

        int n = lifted.Count;
        var labels = new CilInstructionLabel[n + 1];
        for (int i = 0; i <= n; i++) labels[i] = new CilInstructionLabel();
        var startIndex = new int[n + 1];

        var instrs = body.Instructions;
        for (int i = 0; i < n; i++)
        {
            startIndex[i] = instrs.Count;
            foreach (var op in lifted[i])
                instrs.Add(Lower(module, runtimeModule, importer, target, locals, temps, labels, op, i,
                    decoded.ExceptionHandlers));
        }
        startIndex[n] = instrs.Count;

        // A trailing ret backs the end label and any out-of-range branch (the VM ends its dispatch
        // loop when IP runs past the table) — but skip it if the method's own lifted ops already end
        // in one (e.g. the last VM instruction was itself a `ret`); two in a row is dead code that
        // trips AsmResolver's stack calculator.
        if (instrs.Count == 0 || instrs[^1].OpCode.Code != CilCode.Ret)
        {
            var returnType = target.Signature!.ReturnType;
            if (!returnType.IsTypeOf("System", "Void"))
            {
                // This position can land here as dead code after e.g. a trailing `throw` (the VM's
                // own bytecode was itself just an unconditional throw), or as a real branch target
                // for an out-of-range dispatch jump — either way, a bare `ret` is invalid CIL for a
                // non-void method (PEVerify: "return value missing on the stack"). `initobj` works
                // uniformly on reference and value types alike (nulling the former), so producing
                // default(T) here needs no type-category branching.
                var defaultTemp = new CilLocalVariable(importer.ImportTypeSignature(returnType));
                body.LocalVariables.Add(defaultTemp);
                instrs.Add(new CilInstruction(CilOpCodes.Ldloca, defaultTemp));
                instrs.Add(new CilInstruction(CilOpCodes.Initobj, returnType.ToTypeDefOrRef()));
                instrs.Add(new CilInstruction(CilOpCodes.Ldloc, defaultTemp));
            }
            instrs.Add(new CilInstruction(CilOpCodes.Ret));
        }

        for (int i = n; i >= 0; i--)
            labels[i].Instruction = instrs[Math.Min(startIndex[i], instrs.Count - 1)];

        // A protected region can never be exited by falling off its end either — same ECMA-335 rule
        // as the branch case above, just with no branch instruction present at all to convert. The VM
        // only emits an explicit terminator at a region boundary when its own bytecode had a branch
        // there; a region whose last VM instruction simply flows into the next one (e.g. a one-instruction
        // `catch { }` body ending in `pop`) leaves nothing to convert, so insert the missing `leave`.
        //
        // Positions are collected against the pre-insertion `startIndex` and applied highest-first so
        // each insertion leaves lower, not-yet-applied positions valid. Locating the boundary instruction
        // by instance instead (`instrs.IndexOf(label.Instruction)`) would be wrong here: CilInstruction
        // equality is value-based, and this method repeats identical instructions (e.g. the same
        // `call mX4=(Type)` helper call) dozens of times, so IndexOf can resolve to an unrelated
        // earlier occurrence instead of the actual boundary.
        var leaveInsertions = new List<(int Pos, CilInstructionLabel Exit)>();
        foreach (var eh in decoded.ExceptionHandlers)
        {
            var exit = labels[Math.Clamp(eh.HandlerEnd + 1, 0, n)];
            CollectLeaveInsertion(instrs, startIndex, Math.Clamp(eh.TryEnd + 1, 0, n), exit, leaveInsertions);
            CollectLeaveInsertion(instrs, startIndex, Math.Clamp(eh.HandlerEnd + 1, 0, n), exit, leaveInsertions);
        }
        foreach (var (pos, exit) in leaveInsertions.OrderByDescending(x => x.Pos))
            instrs.Insert(pos, new CilInstruction(CilOpCodes.Leave, exit));

        foreach (var eh in decoded.ExceptionHandlers)
            body.ExceptionHandlers.Add(BuildHandler(module, labels, n, eh));

        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        instrs.CalculateOffsets();
        if (Environment.GetEnvironmentVariable("DBG_CIL") == target.MetadataToken.ToInt32().ToString("X8"))
            foreach (var i in instrs)
                Console.Error.WriteLine($"  IL_{i.Offset:X4}: {i}");

        // ComputeMaxStack needs body.Owner (e.g. to know whether `ret` pops a value, from the
        // method's return type) — assign it now to establish Owner, but roll back to the original
        // body if validation fails, so a rejected method stays virtualized rather than broken.
        var original = target.CilMethodBody;
        target.CilMethodBody = body;
        try
        {
            body.ComputeMaxStack();
            CilTypeSafetyValidator.Validate(body);
            return body;
        }
        catch
        {
            target.CilMethodBody = original;
            throw;
        }
    }

    private static CilInstruction Lower(ModuleDefinition module, ModuleDefinition runtimeModule,
                                        ReferenceImporter importer, MethodDefinition target,
                                        CilLocalVariable[] locals, CilLocalVariable[] temps, CilInstructionLabel[] labels, LiftedOp op,
                                        int vmIndex, List<EhClause> ehClauses)
    {
        var code = op.OpCode.Code;
        object? operand = op.Operand;

        if (code is CilCode.Ldloc or CilCode.Stloc or CilCode.Ldloca && operand is int li)
            return new CilInstruction(op.OpCode, locals[li]);
        if (code is CilCode.Ldarg or CilCode.Ldarga && operand is int ai)
            return new CilInstruction(op.OpCode, Arg(target, ai));
        if (operand is TempLocalRef tr)
            return new CilInstruction(op.OpCode, temps[tr.Index]);

        if (operand is VmTarget t)
        {
            var label = labels[Math.Min(t.Index, labels.Length - 1)];
            // A plain `br`/`brtrue`/`brfalse` cannot cross a try or handler boundary — verifiable
            // CIL requires `leave` to exit a protected region. `leave` is unconditional (it takes no
            // stack input and unwinds through every enclosing region between source and target in one
            // step), so a conditional branch that needs to exit would require a trampoline (branch to
            // an in-region label that then leaves) — not yet implemented, so reject rather than emit
            // invalid IL; the method stays virtualized (honest partial output) instead of PEVerify-broken.
            if (ExitsProtectedRegion(ehClauses, vmIndex, t.Index))
            {
                if (code is CilCode.Br or CilCode.Br_S)
                    return new CilInstruction(CilOpCodes.Leave, label);
                throw new LiftUnsupported("conditional branch exits a protected region (leave-trampoline not supported)");
            }
            return new CilInstruction(op.OpCode, label);
        }
        if (operand is VmTarget[] table)
        {
            // `switch` has no leave-equivalent form — any branch table entry that exits a protected
            // region would need the same trampoline `Br`/`Brtrue` support, which doesn't exist.
            if (table.Any(x => ExitsProtectedRegion(ehClauses, vmIndex, x.Index)))
                throw new LiftUnsupported("switch target exits a protected region (leave-trampoline not supported)");
            return new CilInstruction(op.OpCode,
                table.Select(x => (ICilLabel)labels[Math.Min(x.Index, labels.Length - 1)]).ToList());
        }
        if (operand is GetTypeFromHandleMarker)
            return new CilInstruction(op.OpCode, GetTypeFromHandleRef(module));
        if (operand is StringFromCharsCtorMarker)
            return new CilInstruction(op.OpCode, StringFromCharsCtorRef(module));

        switch (operand)
        {
            // A cross-assembly MemberReference implements BOTH IMethodDescriptor and IFieldDescriptor
            // generically (its kind is only decided by its own signature blob) — must disambiguate by
            // that signature BEFORE the interface-based cases below, or a field reference (e.g.
            // String.Empty, Registry.LocalMachine) silently matches `case IMethodDescriptor` first
            // and gets imported as a method, which AsmResolver then rejects at resolve time.
            case MemberReference { Signature: FieldSignature } fref:
            {
                IFieldDescriptor f = fref;
                EnsureCrossModuleVisible(module, runtimeModule, TryResolve(f, module));
                return new CilInstruction(op.OpCode, importer.ImportField(f));
            }
            case MemberReference { Signature: MethodSignature } mref:
            {
                IMethodDescriptor m2 = mref;
                EnsureCrossModuleVisible(module, runtimeModule, TryResolve(m2, module));
                return new CilInstruction(op.OpCode, ImportMethod(module, importer, m2));
            }
            case IMethodDescriptor m:
                EnsureCrossModuleVisible(module, runtimeModule, TryResolve(m, module));
                return new CilInstruction(op.OpCode, ImportMethod(module, importer, m));
            case IFieldDescriptor f:
                EnsureCrossModuleVisible(module, runtimeModule, TryResolve(f, module));
                return new CilInstruction(op.OpCode, importer.ImportField(f));
            case ITypeDefOrRef ty:
                EnsureCrossModuleVisible(module, runtimeModule, TryResolve(ty, module));
                return new CilInstruction(op.OpCode, importer.ImportType(ty));
            case null:
                return new CilInstruction(op.OpCode);
            default:
                return new CilInstruction(op.OpCode, operand);
        }
    }

    /// <summary>
    /// Resolves a method/field/type reference defensively — most references here are ordinary BCL
    /// calls with no accessibility concern, and resolving them can legitimately fail (an assembly
    /// not on the resolver's search path) without that being any fault of the emitted CIL itself.
    /// </summary>
    private static IMemberDefinition? TryResolve(IMethodDescriptor m, ModuleDefinition module)
    {
        try { return m.Resolve(module.RuntimeContext); } catch { return null; }
    }

    private static IMemberDefinition? TryResolve(IFieldDescriptor f, ModuleDefinition module)
    {
        try { return f.Resolve(module.RuntimeContext); } catch { return null; }
    }

    private static IMemberDefinition? TryResolve(ITypeDefOrRef ty, ModuleDefinition module)
    {
        try { return ty.Resolve(module.RuntimeContext); } catch { return null; }
    }

    /// <summary>
    /// A devirtualized method may still call a small transparent runtime helper (a comparison
    /// primitive, a numeric-conversion dispatcher, …) whose original declaration is
    /// <c>internal</c> — valid when the VM's own dispatch loop called it from inside the runtime
    /// assembly, but a cross-assembly access violation once the devirtualized method calls it
    /// directly from the TARGET assembly. Widening the specific referenced members (and their
    /// declaring type chain) to public preserves the exact original behaviour — only the
    /// accessibility changes, not the implementation — for exactly the handful of members we end
    /// up actually calling, nothing else in the runtime assembly is touched.
    /// </summary>
    private static void EnsureCrossModuleVisible(ModuleDefinition targetModule, ModuleDefinition runtimeModule,
                                                 IMemberDefinition? def)
    {
        if (def is null) return;
        var owningModule = (def as TypeDefinition)?.DeclaringModule ?? def.DeclaringType?.DeclaringModule;
        if (owningModule == targetModule || owningModule != runtimeModule) return;

        switch (def)
        {
            case MethodDefinition { IsPublic: false } m: m.IsPublic = true; break;
            case FieldDefinition { IsPublic: false } f: f.IsPublic = true; break;
        }

        // Widen the declaring type chain too — a public method on a non-public (or non-nested-
        // public) type is still unreachable. Start from `def` itself when IT is a type (e.g. an
        // internal enum used directly as a box/newarr/ldtoken operand, not just a member's
        // declaring type), otherwise from its declaring type.
        for (var t = def as TypeDefinition ?? def.DeclaringType; t is not null; t = t.DeclaringType)
        {
            if (t.DeclaringType is null) { if (!t.IsPublic) t.IsPublic = true; }
            else if (!t.IsNestedPublic) t.IsNestedPublic = true;
        }
    }

    /// <summary>
    /// Imports a method reference, falling back to its resolved definition when the reference
    /// itself carries no signature (observed on some obfuscated cross-module member refs) — the
    /// definition always has one, since it IS the method's own declaration.
    /// </summary>
    private static IMethodDescriptor ImportMethod(ModuleDefinition module, ReferenceImporter importer, IMethodDescriptor m)
    {
        try { return importer.ImportMethod(m); }
        catch (ArgumentException) when (m.Signature is null)
        {
            var resolved = m.Resolve(module.RuntimeContext)
                ?? throw new InvalidOperationException($"method reference {m} has no signature and does not resolve");
            return importer.ImportMethod(resolved);
        }
    }

    /// <summary>
    /// Builds a reference to <c>System.Type.GetTypeFromHandle(RuntimeTypeHandle)</c> resolved against
    /// the TARGET module's own corlib — never via <c>typeof(Type)</c>/reflection, since that would
    /// import a MethodInfo bound to whatever corlib THIS TOOL happens to run on (e.g. .NET 8's
    /// System.Private.CoreLib), producing a token the target's own (possibly .NET Framework) runtime
    /// can never resolve.
    /// </summary>
    private static IMethodDescriptor GetTypeFromHandleRef(ModuleDefinition module)
    {
        var corlib = module.CorLibTypeFactory.CorLibScope;
        var typeRef = new TypeReference(module, corlib, "System", "Type");
        var handleRef = new TypeReference(module, corlib, "System", "RuntimeTypeHandle");
        var sig = MethodSignature.CreateStatic(typeRef.ToTypeSignature(isValueType: false), [handleRef.ToTypeSignature(isValueType: true)]);
        return new MemberReference(typeRef, "GetTypeFromHandle", sig);
    }

    /// <summary>Builds a target-corlib reference to <c>System.String(char[])</c>.</summary>
    private static IMethodDescriptor StringFromCharsCtorRef(ModuleDefinition module)
    {
        var corlib = module.CorLibTypeFactory.CorLibScope;
        var stringRef = new TypeReference(module, corlib, "System", "String");
        var charArray = new SzArrayTypeSignature(module.CorLibTypeFactory.Char);
        var sig = MethodSignature.CreateInstance(module.CorLibTypeFactory.Void, [charArray]);
        return new MemberReference(stringRef, ".ctor", sig);
    }

    /// <summary>Opcodes that legally end a protected region — no inserted `leave` needed after these.</summary>
    private static readonly HashSet<CilCode> RegionTerminators =
    [
        CilCode.Leave, CilCode.Leave_S, CilCode.Throw, CilCode.Rethrow, CilCode.Endfinally, CilCode.Ret,
    ];

    /// <summary>
    /// If the instruction immediately preceding VM instruction <paramref name="boundaryVmIndex"/>
    /// doesn't already terminate the region ending there, records a `leave` to insert before it —
    /// converting an implicit fallthrough (illegal across a try/handler boundary) into the required
    /// explicit exit. Looks up the position via the pre-insertion <paramref name="startIndex"/> map
    /// rather than the label's instruction instance, since <c>CilInstructionCollection.IndexOf</c>
    /// compares by value — this method body can (and does) repeat structurally identical instructions,
    /// so an instance lookup can resolve to an unrelated earlier occurrence.
    /// </summary>
    private static void CollectLeaveInsertion(CilInstructionCollection instrs, int[] startIndex, int boundaryVmIndex,
                                               CilInstructionLabel exit, List<(int Pos, CilInstructionLabel Exit)> insertions)
    {
        int pos = startIndex[boundaryVmIndex];
        if (pos <= 0) return;
        if (RegionTerminators.Contains(instrs[pos - 1].OpCode.Code)) return;
        insertions.Add((pos, exit));
    }

    /// <summary>
    /// True when a branch from VM instruction <paramref name="from"/> to <paramref name="to"/> would
    /// cross out of a try or handler region — i.e. <paramref name="from"/> lies inside some clause's
    /// try (or handler) range but <paramref name="to"/> does not, so a plain branch is unverifiable
    /// and the branch must leave the region instead (see the two throw/Leave sites in <see cref="Lower"/>).
    /// A single `leave` legally unwinds through every enclosing region between source and target, so
    /// it is enough to find any one containing region the target escapes — no need to walk nesting.
    /// </summary>
    private static bool ExitsProtectedRegion(List<EhClause> ehClauses, int from, int to)
    {
        foreach (var eh in ehClauses)
        {
            bool fromInTry = from >= eh.TryStart && from <= eh.TryEnd;
            bool toInTry = to >= eh.TryStart && to <= eh.TryEnd;
            if (fromInTry && !toInTry) return true;

            bool fromInHandler = from >= eh.HandlerStart && from <= eh.HandlerEnd;
            bool toInHandler = to >= eh.HandlerStart && to <= eh.HandlerEnd;
            if (fromInHandler && !toInHandler) return true;
        }
        return false;
    }

    private static Parameter Arg(MethodDefinition target, int vmIndex)
    {
        var ps = target.Parameters;
        // VM arg index 0 is `this` for instance methods; the rest are the declared parameters.
        if (ps.ThisParameter is { } self)
            return vmIndex == 0 ? self : ps[vmIndex - 1];
        return ps[vmIndex];
    }

    private static CilExceptionHandler BuildHandler(ModuleDefinition module, CilInstructionLabel[] labels, int n, EhClause eh)
    {
        CilInstructionLabel At(int idx) => labels[Math.Clamp(idx, 0, n)];
        var handler = new CilExceptionHandler
        {
            HandlerType = (CilExceptionHandlerType)eh.ClauseType,
            TryStart = At(eh.TryStart),
            TryEnd = At(eh.TryEnd + 1),          // VM end index is inclusive; CIL end is exclusive
            HandlerStart = At(eh.HandlerStart),
            HandlerEnd = At(eh.HandlerEnd + 1),
        };
        if (eh.ClauseType == 0 && eh.HasExtraToken
            && module.TryLookupMember(new MetadataToken((uint)eh.ExtraToken), out var m)
            && m is ITypeDefOrRef catchType)
            handler.ExceptionType = module.DefaultImporter.ImportType(catchType);
        return handler;
    }
}
