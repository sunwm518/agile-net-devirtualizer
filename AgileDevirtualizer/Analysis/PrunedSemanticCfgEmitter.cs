using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Emit;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

/// <summary>
/// Emits only executable blocks from a verified optimized CFG. The first activation gate is
/// deliberately restricted to methods without exception regions; EH-aware layout remains on the
/// lossless SemanticCfgEmitter route until region-preserving block scheduling is implemented.
/// </summary>
internal static class PrunedSemanticCfgEmitter
{
    public static CilMethodBody Emit(
        ModuleDefinition module,
        MethodDefinition target,
        DecodedMethod decoded,
        SemanticControlFlowGraph graph,
        IReadOnlyList<TypeSignature> tempLocalTypes)
    {
        if (decoded.ExceptionHandlers.Count != 0 || graph.ExceptionRegions.Count != 0)
            throw new InvalidOperationException("pruned CFG emission does not yet support EH");
        var originalBody = target.CilMethodBody;
        var analysis = WorklistAnalyzer.Analyze(graph);
        if (!analysis.Converged)
            throw new InvalidOperationException("optimized CFG worklist did not converge");
        var reachable = graph.Blocks.Where(block => analysis.Blocks[block.Id].Entry.Reachable)
            .Select(block => block.Id).ToHashSet();
        if (reachable.Count == 0 || !reachable.Contains(0))
            throw new InvalidOperationException("optimized CFG has no reachable entry");

        var order = ReversePostOrder(graph, reachable);
        var labels = reachable.ToDictionary(id => id, _ => new CilInstructionLabel());
        var starts = new Dictionary<int, int>();
        var shadowOwner = new MethodDefinition(target.Name, target.Attributes,
            target.Signature ?? throw new InvalidOperationException("target has no signature"),
            verify: false);
        var body = new CilMethodBody
        {
            InitializeLocals = decoded.Locals.Count > 0 || tempLocalTypes.Count > 0,
        };
        shadowOwner.CilMethodBody = body;
        var importer = module.DefaultImporter;
        var locals = SemanticCfgEmitter.AddLocals(body, importer, decoded.Locals);
        var temps = SemanticCfgEmitter.AddLocals(body, importer, tempLocalTypes);

        for (int position = 0; position < order.Count; position++)
        {
            int blockId = order[position];
            var block = graph.Blocks[blockId];
            starts[blockId] = body.Instructions.Count;
            foreach (var operation in block.Operations)
                body.Instructions.Add(SemanticCfgEmitter.LowerOperation(
                    module, importer, target, locals, temps, operation));
            int? nextBlockId = position + 1 < order.Count ? order[position + 1] : null;
            foreach (var instruction in SsaTerminatorLowerer.Lower(
                block, graph, labels, nextBlockId))
                body.Instructions.Add(instruction);
        }
        if (body.Instructions.Count == 0)
            throw new InvalidOperationException("optimized CFG emitted an empty method");
        for (int position = order.Count - 1; position >= 0; position--)
        {
            int blockId = order[position];
            int index = starts[blockId];
            labels[blockId].Instruction = body.Instructions[
                Math.Min(index, body.Instructions.Count - 1)];
        }

        CilConstructorNormalizer.MoveParameterlessBaseCallBeforeThisUse(body, target);
        CilCallArgumentAdapter.RestoreProtectedThisReceivers(body, target);
        CilCallArgumentAdapter.BoxValueTypeLastArguments(body);
        CilCallArgumentAdapter.ConstrainManagedPointerReceivers(body);
        body.Instructions.CalculateOffsets();
        body.VerifyLabels(calculateOffsets: false);
        body.ComputeMaxStack();
        CilTypeSafetyValidator.Validate(body);
        shadowOwner.CilMethodBody = null;
        if (!ReferenceEquals(target.CilMethodBody, originalBody))
            throw new InvalidOperationException("pruned shadow emitter changed the target body");
        return body;
    }

    private static IReadOnlyList<int> ReversePostOrder(
        SemanticControlFlowGraph graph,
        IReadOnlySet<int> reachable)
    {
        var seen = new HashSet<int>();
        var postorder = new List<int>();
        Visit(0);
        postorder.Reverse();
        if (postorder.Count != reachable.Count)
            throw new InvalidOperationException("CFG traversal missed a reachable block");
        return postorder;

        void Visit(int blockId)
        {
            if (!reachable.Contains(blockId) || !seen.Add(blockId))
                return;
            foreach (var edge in SsaControlFlow.Outgoing(graph, graph.Blocks[blockId])
                .Where(edge => reachable.Contains(edge.TargetBlockId))
                .OrderByDescending(edge => edge.Kind == ControlFlowEdgeKind.ConditionalFallThrough)
                .ThenBy(edge => edge.TargetBlockId))
                Visit(edge.TargetBlockId);
            postorder.Add(blockId);
        }
    }
}

