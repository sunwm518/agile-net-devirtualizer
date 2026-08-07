using AsmResolver.DotNet;

namespace AgileDevirtualizer.Analysis;

internal static class SemanticEffectClassifier
{
    public static bool IsRemovableIfUnused(SemanticOperation operation) => operation.Code switch
    {
        SemanticOperationCode.Nop or SemanticOperationCode.Prefix
            or SemanticOperationCode.LoadConstant or SemanticOperationCode.LoadNull
            or SemanticOperationCode.LoadString or SemanticOperationCode.LoadToken
            or SemanticOperationCode.LoadFunctionPointer
            or SemanticOperationCode.LoadArgument or SemanticOperationCode.LoadArgumentAddress
            or SemanticOperationCode.StoreArgument
            or SemanticOperationCode.LoadLocal or SemanticOperationCode.LoadLocalAddress
            or SemanticOperationCode.StoreLocal
            or SemanticOperationCode.Add or SemanticOperationCode.Subtract
            or SemanticOperationCode.Multiply
            or SemanticOperationCode.BitwiseAnd or SemanticOperationCode.BitwiseOr
            or SemanticOperationCode.BitwiseXor or SemanticOperationCode.ShiftLeft
            or SemanticOperationCode.ShiftRight or SemanticOperationCode.Negate
            or SemanticOperationCode.BitwiseNot or SemanticOperationCode.CompareEqual
            or SemanticOperationCode.CompareLessThan or SemanticOperationCode.CompareGreaterThan
            or SemanticOperationCode.Duplicate or SemanticOperationCode.Pop =>
            !CanThrowFromArithmetic(operation),
        SemanticOperationCode.Convert =>
            operation.Semantics.Overflow == SemanticOverflowMode.Unchecked,
        SemanticOperationCode.Call or SemanticOperationCode.CallVirtual => IsPureMathAbs(operation),
        _ => false,
    };

    public static bool CanReplaceWithConstant(SsaInstruction instruction) =>
        instruction.Outputs.Count == 1 && IsRemovableIfUnused(instruction.Operation);

    private static bool CanThrowFromArithmetic(SemanticOperation operation) =>
        operation.Semantics.Overflow == SemanticOverflowMode.Checked
        || operation.Code is SemanticOperationCode.Divide or SemanticOperationCode.Remainder;

    private static bool IsPureMathAbs(SemanticOperation operation) =>
        operation.Operand is IMethodDescriptor method
        && method.DeclaringType?.FullName == "System.Math"
        && method.Name?.ToString() == "Abs"
        && method.Signature?.ParameterTypes.Count == 1;
}
