using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Analysis;

internal enum ExceptionEntryKind
{
    CatchHandler,
    FilterEvaluation,
    FilterHandler,
    FinallyHandler,
    FaultHandler,
}

internal sealed record ExceptionObjectContract(
    TypeSignature? StaticType,
    bool NonNull,
    int? SsaValueId);

/// <summary>
/// CLI-created entry state for one catch/filter/finally/fault location. Filter evaluation and its
/// accepted handler are deliberately separate entries because both receive a fresh exception object.
/// </summary>
internal sealed record ExceptionEntry(
    int ExceptionRegionId,
    ExceptionEntryKind Kind,
    int InstructionIndex,
    int BlockId,
    RegionPath RegionPath,
    ControlFlowEdgeKind IncomingEdgeKind,
    ExceptionObjectContract? ExceptionObject)
{
    public int ExpectedStackDepth => ExceptionObject is null ? 0 : 1;
}

internal sealed class ExceptionEntryModel
{
    public ExceptionEntryModel(
        ModuleDefinition module,
        SsaGraph graph,
        IReadOnlyList<ExceptionEntry> entries)
    {
        Module = module;
        Graph = graph;
        Entries = entries;
    }

    public ModuleDefinition Module { get; }
    public SsaGraph Graph { get; }
    public IReadOnlyList<ExceptionEntry> Entries { get; }
}

/// <summary>Builds the formal EH-entry contract without participating in CIL emission.</summary>
internal static class ExceptionEntryModelBuilder
{
    public static ExceptionEntryModel Build(ModuleDefinition module, SsaGraph graph)
    {
        var entries = new List<ExceptionEntry>();
        foreach (var region in graph.Source.ExceptionRegions.OrderBy(region => region.Id))
        {
            switch (region.ClauseKind)
            {
                case ExceptionClauseKind.Catch:
                    Add(entries, graph, region, ExceptionEntryKind.CatchHandler,
                        region.HandlerStart,
                        ControlFlowEdgeKind.ExceptionCatch, ResolveCatchType(module, region));
                    break;
                case ExceptionClauseKind.Filter:
                    if (region.FilterStart is { } filterStart)
                    {
                        Add(entries, graph, region, ExceptionEntryKind.FilterEvaluation,
                            filterStart,
                            ControlFlowEdgeKind.ExceptionFilter, module.CorLibTypeFactory.Object);
                    }
                    Add(entries, graph, region, ExceptionEntryKind.FilterHandler,
                        region.HandlerStart,
                        ControlFlowEdgeKind.ExceptionFilterHandler, module.CorLibTypeFactory.Object);
                    break;
                case ExceptionClauseKind.Finally:
                    Add(entries, graph, region, ExceptionEntryKind.FinallyHandler,
                        region.HandlerStart,
                        ControlFlowEdgeKind.ExceptionFinally, exceptionType: null);
                    break;
                case ExceptionClauseKind.Fault:
                    Add(entries, graph, region, ExceptionEntryKind.FaultHandler,
                        region.HandlerStart,
                        ControlFlowEdgeKind.ExceptionFault, exceptionType: null);
                    break;
            }
        }
        return new ExceptionEntryModel(module, graph, entries);
    }

    private static void Add(
        ICollection<ExceptionEntry> entries,
        SsaGraph graph,
        ExceptionRegion region,
        ExceptionEntryKind kind,
        int instructionIndex,
        ControlFlowEdgeKind incomingEdgeKind,
        TypeSignature? exceptionType)
    {
        var block = graph.Source.BlockContaining(instructionIndex);
        int? valueId = null;
        var ssaBlock = graph.Blocks[block.Id];
        bool hasExceptionObject = kind is ExceptionEntryKind.CatchHandler
            or ExceptionEntryKind.FilterEvaluation or ExceptionEntryKind.FilterHandler;
        if (hasExceptionObject && ssaBlock.EntryStack.Count == 1)
        {
            var value = graph.Value(ssaBlock.EntryStack[0]);
            if (value.Kind == SsaValueKind.ExceptionObject)
                valueId = value.Id;
        }
        var exceptionObject = hasExceptionObject
            ? new ExceptionObjectContract(exceptionType, NonNull: true, valueId) : null;
        var path = block.RegionPath;
        entries.Add(new ExceptionEntry(region.Id, kind, instructionIndex, block.Id,
            path, incomingEdgeKind, exceptionObject));
    }

    private static TypeSignature? ResolveCatchType(
        ModuleDefinition module,
        ExceptionRegion region)
    {
        if (region.CatchTypeToken is not { } rawToken
            || !module.TryLookupMember(new MetadataToken((uint)rawToken), out var member)
            || member is not ITypeDescriptor descriptor)
            return null;
        try
        {
            return descriptor switch
            {
                TypeSignature signature => signature,
                ITypeDefOrRef reference => reference.ToTypeSignature(false),
                _ => descriptor.ToTypeSignature(descriptor.ContextModule?.RuntimeContext),
            };
        }
        catch
        {
            return null;
        }
    }
}
