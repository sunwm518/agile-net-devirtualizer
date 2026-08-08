using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Lossless migration emitter driven by the formal CFG. The resulting body is owned by a synthetic
/// method that is not attached to any module, and is never assigned to the real target method.
/// Concrete CIL opcodes are selected only by SemanticCilLowerer from target-neutral signedness,
/// overflow, primitive-type, prefix, dispatch and operand-encoding attributes.
/// </summary>
internal static class SemanticCfgEmitter
{
    private static readonly HashSet<CilCode> RegionTerminators =
    [
        CilCode.Leave, CilCode.Leave_S, CilCode.Throw, CilCode.Rethrow,
        CilCode.Endfinally, CilCode.Ret,
    ];

    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        var installedBody = target.CilMethodBody;
        var importer = module.DefaultImporter;
        var shadowOwner = new MethodDefinition(
            target.Name,
            target.Attributes,
            target.Signature
                ?? throw new InvalidOperationException("target method has no signature"),
            verify: false);
        var body = new CilMethodBody
        {
            InitializeLocals = decoded.Locals.Count > 0 || tempLocalTypes.Count > 0,
        };
        shadowOwner.CilMethodBody = body;
        var locals = AddLocals(body, importer, decoded.Locals);
        var temps = AddLocals(body, importer, tempLocalTypes);
        int instructionCount = graph.InstructionCount;
        var labels = Enumerable.Range(0, instructionCount + 1)
            .Select(_ => new CilInstructionLabel()).ToArray();
        var startIndex = new int[instructionCount + 1];
        var operations = graph.Blocks.SelectMany(block => block.Operations)
            .GroupBy(operation => operation.VmInstructionIndex)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var terminators = graph.Blocks.ToDictionary(
            block => block.EndInstructionIndex, block => block);

        for (int vmIndex = 0; vmIndex < instructionCount; vmIndex++)
        {
            startIndex[vmIndex] = body.Instructions.Count;
            if (operations.TryGetValue(vmIndex, out var atIndex))
                foreach (var operation in atIndex)
                    body.Instructions.Add(LowerOperation(
                        module, importer, target, locals, temps, operation));
            if (terminators.TryGetValue(vmIndex, out var block))
            {
                var terminator = LowerTerminator(block, graph, labels);
                if (terminator is not null)
                    body.Instructions.Add(terminator);
            }
        }
        startIndex[instructionCount] = body.Instructions.Count;
        if (body.Instructions.Count == 0 || body.Instructions[^1].OpCode.Code != CilCode.Ret)
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
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloca, defaultTemp));
                body.Instructions.Add(new CilInstruction(CilOpCodes.Initobj, returnType.ToTypeDefOrRef()));
                body.Instructions.Add(new CilInstruction(CilOpCodes.Ldloc, defaultTemp));
            }
            body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
        }
        for (int index = instructionCount; index >= 0; index--)
            labels[index].Instruction = body.Instructions[
                Math.Min(startIndex[index], body.Instructions.Count - 1)];

        InsertRegionLeaves(body.Instructions, decoded.ExceptionHandlers,
            labels, startIndex, instructionCount);
        foreach (var clause in decoded.ExceptionHandlers)
            body.ExceptionHandlers.Add(BuildHandler(module, labels, instructionCount, clause));

        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        body.Instructions.CalculateOffsets();
        body.VerifyLabels(calculateOffsets: false);
        body.ComputeMaxStack();
        CilTypeSafetyValidator.Validate(body);
        shadowOwner.CilMethodBody = null;

        if (!ReferenceEquals(target.CilMethodBody, installedBody))
            throw new InvalidOperationException("shadow CFG emitter changed the installed method body");
        return body;
    }

    internal static CilLocalVariable[] AddLocals(
        CilMethodBody body,
        ReferenceImporter importer,
        IReadOnlyList<TypeSignature> types)
    {
        var result = new CilLocalVariable[types.Count];
        for (int index = 0; index < result.Length; index++)
        {
            result[index] = new CilLocalVariable(importer.ImportTypeSignature(types[index]));
            body.LocalVariables.Add(result[index]);
        }
        return result;
    }

    internal static CilInstruction LowerOperation(
        ModuleDefinition module,
        ReferenceImporter importer,
        MethodDefinition target,
        CilLocalVariable[] locals,
        CilLocalVariable[] temps,
        SemanticOperation operation)
    {
        var opCode = SemanticCilLowerer.Lower(operation);
        if (opCode.OperandType == CilOperandType.InlineNone)
            return new CilInstruction(opCode);

        object? operand = operation.Operand;
        if (operand is SemanticLocalReference local)
            return new CilInstruction(opCode,
                local.Temporary ? temps[local.Index] : locals[local.Index]);
        if (operand is SemanticArgumentReference argument)
            return new CilInstruction(opCode, Arg(target, argument.Index));
        if (operand is GetTypeFromHandleMarker)
            return new CilInstruction(opCode, GetTypeFromHandleRef(module));
        if (operand is StringFromCharsCtorMarker)
            return new CilInstruction(opCode, StringFromCharsCtorRef(module));

        return operand switch
        {
            MemberReference { Signature: FieldSignature } field =>
                new CilInstruction(opCode, importer.ImportField(field)),
            MemberReference { Signature: MethodSignature } method =>
                new CilInstruction(opCode, ImportMethod(module, importer, method)),
            IMethodDescriptor method =>
                new CilInstruction(opCode, ImportMethod(module, importer, method)),
            IFieldDescriptor field =>
                new CilInstruction(opCode, importer.ImportField(field)),
            ITypeDefOrRef type =>
                new CilInstruction(opCode, importer.ImportType(type)),
            null => new CilInstruction(opCode),
            _ => new CilInstruction(opCode, operand),
        };
    }

    private static CilInstruction? LowerTerminator(
        BasicBlock block,
        SemanticControlFlowGraph graph,
        CilInstructionLabel[] labels)
    {
        var terminator = block.Terminator;
        if (terminator.Kind == SemanticTerminatorKind.FallThrough)
            return null;
        bool isLeave = terminator.Kind == SemanticTerminatorKind.Branch
            && graph.Outgoing(block).Any(edge => edge.Kind == ControlFlowEdgeKind.Leave);
        var opCode = SemanticCilLowerer.Lower(terminator, isLeave);
        if (opCode.Code == CilCode.Switch)
            return new CilInstruction(opCode, terminator.TargetInstructionIndices
                .Select(index => (ICilLabel)labels[index]).ToList());
        if (opCode.OperandType is CilOperandType.InlineBrTarget
            or CilOperandType.ShortInlineBrTarget)
        {
            int targetIndex = terminator.TargetInstructionIndices.Single();
            return new CilInstruction(opCode, labels[targetIndex]);
        }
        return new CilInstruction(opCode);
    }

    private static void InsertRegionLeaves(
        CilInstructionCollection instructions,
        IReadOnlyList<EhClause> clauses,
        CilInstructionLabel[] labels,
        int[] startIndex,
        int instructionCount)
    {
        var insertions = new List<(int Position, CilInstructionLabel Exit)>();
        foreach (var clause in clauses)
        {
            var exit = labels[Math.Clamp(clause.HandlerEnd + 1, 0, instructionCount)];
            Collect(clause.TryEnd + 1, exit);
            Collect(clause.HandlerEnd + 1, exit);
        }
        foreach (var insertion in insertions.OrderByDescending(item => item.Position))
            instructions.Insert(insertion.Position,
                new CilInstruction(CilOpCodes.Leave, insertion.Exit));

        void Collect(int boundary, CilInstructionLabel exit)
        {
            int position = startIndex[Math.Clamp(boundary, 0, instructionCount)];
            if (position <= 0 || RegionTerminators.Contains(instructions[position - 1].OpCode.Code))
                return;
            insertions.Add((position, exit));
        }
    }

    private static CilExceptionHandler BuildHandler(
        ModuleDefinition module,
        CilInstructionLabel[] labels,
        int instructionCount,
        EhClause clause)
    {
        CilInstructionLabel At(int index) => labels[Math.Clamp(index, 0, instructionCount)];
        var handler = new CilExceptionHandler
        {
            HandlerType = (CilExceptionHandlerType)clause.ClauseType,
            TryStart = At(clause.TryStart),
            TryEnd = At(clause.TryEnd + 1),
            HandlerStart = At(clause.HandlerStart),
            HandlerEnd = At(clause.HandlerEnd + 1),
        };
        if (clause.ClauseType == 0 && clause.HasExtraToken
            && module.TryLookupMember(new MetadataToken((uint)clause.ExtraToken), out var member)
            && member is ITypeDefOrRef catchType)
            handler.ExceptionType = module.DefaultImporter.ImportType(catchType);
        return handler;
    }

    private static Parameter Arg(MethodDefinition target, int vmIndex)
    {
        if (target.Parameters.ThisParameter is { } self)
            return vmIndex == 0 ? self : target.Parameters[vmIndex - 1];
        return target.Parameters[vmIndex];
    }

    private static IMethodDescriptor ImportMethod(
        ModuleDefinition module,
        ReferenceImporter importer,
        IMethodDescriptor method)
    {
        try { return importer.ImportMethod(method); }
        catch (ArgumentException) when (method.Signature is null)
        {
            var resolved = method.Resolve(module.RuntimeContext)
                ?? throw new InvalidOperationException(
                    $"method reference {method} has no signature and does not resolve");
            return importer.ImportMethod(resolved);
        }
    }

    private static IMethodDescriptor GetTypeFromHandleRef(ModuleDefinition module)
    {
        var corlib = module.CorLibTypeFactory.CorLibScope;
        var type = new TypeReference(module, corlib, "System", "Type");
        var handle = new TypeReference(module, corlib, "System", "RuntimeTypeHandle");
        var signature = MethodSignature.CreateStatic(
            type.ToTypeSignature(false), [handle.ToTypeSignature(true)]);
        return new MemberReference(type, "GetTypeFromHandle", signature);
    }

    private static IMethodDescriptor StringFromCharsCtorRef(ModuleDefinition module)
    {
        var type = new TypeReference(module, module.CorLibTypeFactory.CorLibScope,
            "System", "String");
        var signature = MethodSignature.CreateInstance(module.CorLibTypeFactory.Void,
            [new SzArrayTypeSignature(module.CorLibTypeFactory.Char)]);
        return new MemberReference(type, ".ctor", signature);
    }
}
