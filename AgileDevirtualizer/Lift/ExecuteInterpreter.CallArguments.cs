using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Corrects a stale dynamic local cast only at a direct-call argument boundary. VM locals are
    /// declared as Object and their inferred type can come from another control-flow generation;
    /// when that stale type emitted a sealed, provably incompatible <c>castclass</c>, the reflective
    /// target's concrete parameter type is the authoritative type that the original Invoke required.
    /// Unresolved, assignable, open-generic, value-type, and non-tail casts are left untouched.
    /// </summary>
    private void NarrowReferenceArguments(IMethodDescriptor target)
    {
        if (target.Signature is not { } signature || signature.ParameterTypes.Count == 0)
            return;

        var context = GenericContext.FromMethod(target);
        var expectedTypes = signature.ParameterTypes
            .Select(parameter => parameter.InstantiateGenericTypes(context))
            .ToArray();
        int end = _out.Count;

        for (int parameterIndex = expectedTypes.Length - 1; parameterIndex >= 0; parameterIndex--)
        {
            if (!TryTailExpressionStart(end, out int start))
                return;

            TypeSignature expected = expectedTypes[parameterIndex];
            if (IsConcreteReferenceType(expected)
                && _out[end - 1] is { OpCode.Code: CilCode.Castclass, Operand: ITypeDefOrRef staleCast }
                && (IsSystemObject(staleCast) || IsProvenIncompatibleSealedCast(staleCast, expected)))
            {
                _out[end - 1] = new LiftedOp(CilOpCodes.Castclass, expected.ToTypeDefOrRef());
            }
            else if (IsConcreteReferenceType(expected) && TailProducesSystemObject(end))
            {
                // Reflection performed this reference conversion before invoking the target. A
                // direct call has no binder, so make the required narrowing explicit when the
                // complete argument expression is still statically only Object.
                _out.Insert(end, new LiftedOp(CilOpCodes.Castclass, expected.ToTypeDefOrRef()));
            }

            end = start;
        }
    }

    private bool TryTailExpressionStart(int end, out int start)
    {
        for (start = end - 1; start >= 0; start--)
        {
            if (IsOutputControlFlowBoundary(_out[start]))
                break;
            if (TryOutputSegmentNetStack(start, end, out int net) && net == 1)
                return true;
        }
        start = -1;
        return false;
    }

    private bool TryOutputSegmentNetStack(int start, int end, out int net)
    {
        net = 0;
        for (int i = start; i < end; i++)
        {
            int delta = NetDelta(_out[i]);
            if (delta == int.MinValue)
                return false;
            net += delta;
            if (net < 0)
                return false;
        }
        return true;
    }

    private bool IsProvenIncompatibleSealedCast(ITypeDefOrRef staleCast, TypeSignature expected)
    {
        try
        {
            TypeSignature? actual = TypeSignatureOf(staleCast);
            var actualDefinition = ResolveTypeDef(staleCast);
            var expectedDefinition = ResolveTypeDef(expected);
            return actual is not null
                && actualDefinition is { IsSealed: true }
                && expectedDefinition is { IsInterface: false }
                && !actual.IsAssignableTo(expected, _ctx);
        }
        catch { return false; }
    }

    private bool TailProducesSystemObject(int end)
    {
        if (end <= 0)
            return false;

        var operation = _out[end - 1];
        TypeSignature? type = operation.OpCode.Code switch
        {
            CilCode.Call or CilCode.Callvirt when operation.Operand is IMethodDescriptor method
                => SigReturn(method),
            CilCode.Ldfld or CilCode.Ldsfld when operation.Operand is IFieldDescriptor field
                => field.Signature?.FieldType,
            CilCode.Ldloc when operation.Operand is int index
                => DeclaredType(_vmLocalTypes, index),
            CilCode.Ldarg when operation.Operand is int index
                => DeclaredType(_vmArgTypes, index),
            _ => null,
        };
        return type?.IsTypeOf("System", "Object") == true;
    }

    private bool IsSystemObject(ITypeDefOrRef type)
    {
        try { return TypeSignatureOf(type)?.IsTypeOf("System", "Object") == true; }
        catch { return false; }
    }

    private static bool IsConcreteReferenceType(TypeSignature type) =>
        !type.IsValueType
        && type is not GenericParameterSignature
        && type is not ByReferenceTypeSignature
        && type is not PointerTypeSignature
        && type is not FunctionPointerTypeSignature
        && type.FullName?.Contains('!') != true;

    private static bool IsOutputControlFlowBoundary(LiftedOp operation) => operation.OpCode.FlowControl is
        CilFlowControl.Branch or CilFlowControl.ConditionalBranch or CilFlowControl.Return or CilFlowControl.Throw;
}
