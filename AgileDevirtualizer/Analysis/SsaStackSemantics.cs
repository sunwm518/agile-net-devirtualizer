using AgileDevirtualizer.Lift;
using AsmResolver.DotNet;

namespace AgileDevirtualizer.Analysis;

internal enum SsaOperationBehavior
{
    NoEffect,
    General,
    LoadVariable,
    StoreVariable,
    Duplicate,
    Pop,
}

internal readonly record struct SsaOperationEffect(
    SsaOperationBehavior Behavior,
    int PopCount,
    int PushCount);

/// <summary>Target-neutral evaluation-stack effects for Semantic IR.</summary>
internal static class SsaStackSemantics
{
    public static SsaOperationEffect ForOperation(SemanticOperation operation) => operation.Code switch
    {
        SemanticOperationCode.Nop or SemanticOperationCode.Prefix => NoEffect(),
        SemanticOperationCode.LoadConstant or SemanticOperationCode.LoadNull
            or SemanticOperationCode.LoadString or SemanticOperationCode.LoadToken
            or SemanticOperationCode.LoadFunctionPointer => General(0, 1),
        SemanticOperationCode.LoadArgument or SemanticOperationCode.LoadLocal =>
            new(SsaOperationBehavior.LoadVariable, 0, 1),
        SemanticOperationCode.StoreArgument or SemanticOperationCode.StoreLocal =>
            new(SsaOperationBehavior.StoreVariable, 1, 0),
        SemanticOperationCode.LoadArgumentAddress or SemanticOperationCode.LoadLocalAddress =>
            General(0, 1),
        SemanticOperationCode.LoadField => General(1, 1),
        SemanticOperationCode.LoadStaticField => General(0, 1),
        SemanticOperationCode.StoreField => General(2, 0),
        SemanticOperationCode.StoreStaticField => General(1, 0),
        SemanticOperationCode.LoadElement or SemanticOperationCode.LoadElementAddress => General(2, 1),
        SemanticOperationCode.StoreElement => General(3, 0),
        SemanticOperationCode.LoadObject => General(1, 1),
        SemanticOperationCode.StoreObject => General(2, 0),
        SemanticOperationCode.LoadArrayLength => General(1, 1),
        SemanticOperationCode.NewArray => General(1, 1),
        SemanticOperationCode.Add or SemanticOperationCode.Subtract
            or SemanticOperationCode.Multiply or SemanticOperationCode.Divide
            or SemanticOperationCode.Remainder or SemanticOperationCode.BitwiseAnd
            or SemanticOperationCode.BitwiseOr or SemanticOperationCode.BitwiseXor
            or SemanticOperationCode.ShiftLeft or SemanticOperationCode.ShiftRight
            or SemanticOperationCode.CompareEqual or SemanticOperationCode.CompareLessThan
            or SemanticOperationCode.CompareGreaterThan => General(2, 1),
        SemanticOperationCode.Negate or SemanticOperationCode.BitwiseNot
            or SemanticOperationCode.Convert or SemanticOperationCode.Box
            or SemanticOperationCode.UnboxAddress or SemanticOperationCode.UnboxValue
            or SemanticOperationCode.Cast or SemanticOperationCode.IsInstance => General(1, 1),
        SemanticOperationCode.Call or SemanticOperationCode.CallVirtual => Call(operation.Operand),
        SemanticOperationCode.NewObject => NewObject(operation.Operand),
        SemanticOperationCode.Duplicate => new(SsaOperationBehavior.Duplicate, 0, 1),
        SemanticOperationCode.Pop => new(SsaOperationBehavior.Pop, 1, 0),
        SemanticOperationCode.InitializeObject => General(1, 0),
        _ => throw new InvalidOperationException(
            $"SSA stack effect is not defined for {operation.Code}"),
    };

    public static int TerminatorPopCount(SemanticTerminator terminator, bool returnsValue) =>
        terminator.Kind switch
        {
            SemanticTerminatorKind.Conditional => terminator.Semantics.Predicate is
                SemanticBranchPredicate.True or SemanticBranchPredicate.False ? 1 : 2,
            SemanticTerminatorKind.Switch or SemanticTerminatorKind.Throw
                or SemanticTerminatorKind.EndFilter => 1,
            SemanticTerminatorKind.Return when returnsValue => 1,
            _ => 0,
        };

    private static SsaOperationEffect Call(object? operand)
    {
        if (operand is GetTypeFromHandleMarker)
            return General(1, 1);
        if (operand is not IMethodDescriptor method || method.Signature is not { } signature)
            throw new InvalidOperationException("SSA cannot determine the call signature");
        int pops = signature.ParameterTypes.Count + (signature.HasThis ? 1 : 0);
        int pushes = signature.ReturnType.IsTypeOf("System", "Void") ? 0 : 1;
        return General(pops, pushes);
    }

    private static SsaOperationEffect NewObject(object? operand)
    {
        if (operand is StringFromCharsCtorMarker)
            return General(1, 1);
        if (operand is not IMethodDescriptor constructor
            || constructor.Signature is not { } signature)
            throw new InvalidOperationException("SSA cannot determine the constructor signature");
        return General(signature.ParameterTypes.Count, 1);
    }

    private static SsaOperationEffect NoEffect() =>
        new(SsaOperationBehavior.NoEffect, 0, 0);

    private static SsaOperationEffect General(int pops, int pushes) =>
        new(SsaOperationBehavior.General, pops, pushes);
}
