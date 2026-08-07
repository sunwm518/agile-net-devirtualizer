using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    private HandlerInfo _currentHandler = null!;

    /// <summary>
    /// Establishes the native CLR stack state at the entry of a decoded catch region. Regardless of
    /// the linear bytecode instruction that precedes the handler, the CLR enters a catch with exactly
    /// one value on the evaluation stack: the caught exception. Resetting the VM stack shadow here
    /// prevents values from mutually-exclusive throw paths leaking into the handler state.
    /// </summary>
    private void PrepareExceptionHandlerEntry()
    {
        var handler = _vmExceptionHandlers.FirstOrDefault(eh =>
            eh.ClauseType == 0 && eh.HandlerStart == _instr.Index);
        if (handler is null)
            return;

        TypeSignature? catchType = null;
        if (handler.HasExtraToken
            && _module.TryLookupMember(new MetadataToken((uint)handler.ExtraToken), out var member)
            && member is ITypeDescriptor descriptor)
            catchType = TypeSignatureOf(descriptor);

        _vmValueTypes.Clear();
        _vmValueTypes.Push(new VmStackType(catchType, ManagedPointer: false, KnownNull: false));
    }

    /// <summary>
    /// Recognizes the VM context's current-exception accessor by ownership and CLR signature. Names
    /// are randomized per protection build; a parameterless instance method on the known context
    /// type returning an Exception-derived value is the stable semantic identity.
    /// </summary>
    private bool TryHandleCurrentExceptionAccessor(IMethodDescriptor method, MethodDefinition? definition)
    {
        if (definition is null
            || !ReferenceEquals(definition.DeclaringType, _vocab.ContextType)
            || definition.IsStatic
            || ParamCount(method) != 0
            || SigReturn(method) is not { } returnType
            || !IsExceptionType(returnType))
            return false;

        var receiver = Pop();
        if (receiver is not SymValue.Ctx)
            throw new LiftUnsupported("current-exception accessor without VM context receiver");
        _eval.Push(new SymValue.CurrentException());
        return true;
    }

    /// <summary>
    /// Converts a throw of the VM context's current exception at the inclusive end of a catch
    /// handler into native <c>rethrow</c>. Restricting it to a decoded catch terminator prevents an
    /// ordinary source <c>throw ex</c> from being rewritten with different stack-trace semantics.
    /// </summary>
    private bool TryEmitRethrow(SymValue exception)
    {
        if (exception is not SymValue.CurrentException
            || !_vmExceptionHandlers.Any(eh =>
                eh.ClauseType == 0 && eh.HandlerEnd == _instr.Index))
            return false;

        Emit(CilOpCodes.Rethrow);
        _termKind = TermKind.Resolved;
        return true;
    }

    /// <summary>
    /// Replaces the VM runtime's exception-frame dispatch with the native CIL terminator belonging
    /// to the original finally/fault handler. Agile handlers implement <c>endfinally</c> by popping
    /// a private exception frame and switching between resume, rethrow and internal-error paths.
    /// That switch is VM machinery, not source control flow. Some builds fuse useful work (for
    /// example a constrained Dispose call) before the same tail, so recognition happens when the
    /// tail is reached and preserves every operation already emitted by the symbolic interpreter.
    /// </summary>
    private bool TryEmitExceptionHandlerTerminator(CilInstruction switchInstruction)
    {
        if (!_vmExceptionHandlers.Any(eh =>
                eh.HandlerEnd == _instr.Index && eh.ClauseType is 2 or 4))
            return false;

        if (!IsVmExceptionFrameDispatch(_currentHandler, switchInstruction))
            return false;

        Emit(CilOpCodes.Endfinally);
        _termKind = TermKind.Resolved;
        return true;
    }

    /// <summary>
    /// Identifies the runtime unwind dispatcher structurally. Its execute body has one switch,
    /// offers a resume arm through the context's SetIp primitive, and has exception-throwing arms.
    /// Requiring the current VM instruction to be the decoded EH handler's inclusive end (above)
    /// prevents an ordinary source switch from being mistaken for an exception terminator.
    /// </summary>
    private bool IsVmExceptionFrameDispatch(HandlerInfo handler, CilInstruction candidate)
    {
        if (handler.ExecuteMethod?.CilMethodBody is not { } body)
            return false;

        var switches = body.Instructions
            .Where(i => i.OpCode.Code == CilCode.Switch)
            .ToList();
        if (switches.Count != 1 || !ReferenceEquals(switches[0], candidate))
            return false;

        bool resumesViaIp = false;
        int throws = 0;
        foreach (var instruction in body.Instructions)
        {
            if (instruction.OpCode.Code == CilCode.Throw)
                throws++;

            if (instruction.OpCode.Code is not (CilCode.Call or CilCode.Callvirt)
                || instruction.Operand is not IMethodDescriptor called)
                continue;

            if (Same(ResolveM(called), _vocab.SetIp))
                resumesViaIp = true;
        }

        return resumesViaIp && throws >= 2;
    }
}
