namespace AgileDevirtualizer.Analysis;

/// <summary>CLI exception-system semantics attached to formal CFG edge kinds.</summary>
internal static class ControlFlowEdgeSemantics
{
    public static bool IsException(ControlFlowEdgeKind kind) => kind is
        ControlFlowEdgeKind.ExceptionCatch
        or ControlFlowEdgeKind.ExceptionFilter
        or ControlFlowEdgeKind.ExceptionFilterHandler
        or ControlFlowEdgeKind.ExceptionFinally
        or ControlFlowEdgeKind.ExceptionFault;

    public static bool SeedsExceptionObject(ControlFlowEdgeKind kind) => kind is
        ControlFlowEdgeKind.ExceptionCatch
        or ControlFlowEdgeKind.ExceptionFilter
        or ControlFlowEdgeKind.ExceptionFilterHandler;
}
