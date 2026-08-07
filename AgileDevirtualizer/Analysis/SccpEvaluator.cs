using AsmResolver.DotNet;

namespace AgileDevirtualizer.Analysis;

internal readonly record struct SccpTerminatorDecision(
    bool Known,
    bool ConditionalTaken = false,
    int? SwitchIndex = null);

internal static class SccpEvaluator
{
    public static SccpValue Evaluate(
        SsaInstruction instruction,
        IReadOnlyList<SccpValue> inputs,
        AbstractValue outputType,
        out bool foldedPureCall)
    {
        foldedPureCall = false;
        var operation = instruction.Operation;
        if (operation.Code == SemanticOperationCode.LoadConstant)
            return SccpValue.FromConstant(operation.Operand);
        if (operation.Code == SemanticOperationCode.LoadNull)
            return SccpValue.FromConstant(null);
        if (operation.Code == SemanticOperationCode.LoadString)
            return SccpValue.FromConstant(operation.Operand);
        if (inputs.Any(value => value.Kind == SccpValueKind.Undefined))
            return SccpValue.Undefined;
        if (inputs.Any(value => value.Kind == SccpValueKind.Overdefined))
            return SccpValue.Overdefined;

        object?[] constants = inputs.Select(value => value.Constant).ToArray();
        try
        {
            if (operation.Code is SemanticOperationCode.Call or SemanticOperationCode.CallVirtual
                && TryFoldPureCall(operation, constants, out var callResult))
            {
                foldedPureCall = true;
                return SccpValue.FromConstant(callResult);
            }
            if (operation.Code is SemanticOperationCode.Add or SemanticOperationCode.Subtract
                or SemanticOperationCode.Multiply or SemanticOperationCode.Divide
                or SemanticOperationCode.Remainder or SemanticOperationCode.BitwiseAnd
                or SemanticOperationCode.BitwiseOr or SemanticOperationCode.BitwiseXor
                or SemanticOperationCode.ShiftLeft or SemanticOperationCode.ShiftRight)
            {
                return TryBinary(operation, constants, outputType, out var binary)
                    ? SccpValue.FromConstant(binary) : SccpValue.Overdefined;
            }
            if (operation.Code is SemanticOperationCode.Negate or SemanticOperationCode.BitwiseNot)
            {
                return TryUnary(operation.Code, constants[0], outputType, out var unary)
                    ? SccpValue.FromConstant(unary) : SccpValue.Overdefined;
            }
            if (operation.Code is SemanticOperationCode.CompareEqual
                or SemanticOperationCode.CompareLessThan
                or SemanticOperationCode.CompareGreaterThan)
            {
                return TryCompare(operation, constants[0], constants[1], out bool comparison)
                    ? SccpValue.FromConstant(comparison ? 1 : 0) : SccpValue.Overdefined;
            }
            if (operation.Code == SemanticOperationCode.Convert)
            {
                return TryConvert(operation.Semantics, constants[0], out var converted)
                    ? SccpValue.FromConstant(converted) : SccpValue.Overdefined;
            }
        }
        catch (ArithmeticException)
        {
            // The operation can throw on this path. Do not replace it with a value.
        }
        return SccpValue.Overdefined;
    }

    public static SccpTerminatorDecision Decide(
        SsaTerminator terminator,
        IReadOnlyDictionary<int, SccpValue> values)
    {
        var semantic = terminator.Terminator;
        if (semantic.Kind == SemanticTerminatorKind.Switch)
        {
            if (terminator.Inputs.Count == 1
                && values[terminator.Inputs[0]] is { Kind: SccpValueKind.Constant } selector
                && TryInt64(selector.Constant, out long index))
                return new SccpTerminatorDecision(true, SwitchIndex: unchecked((int)index));
            return default;
        }
        if (semantic.Kind != SemanticTerminatorKind.Conditional)
            return default;
        var inputs = terminator.Inputs.Select(id => values[id]).ToArray();
        if (inputs.Any(value => value.Kind != SccpValueKind.Constant))
            return default;
        bool? taken = semantic.Semantics.Predicate switch
        {
            SemanticBranchPredicate.True => Truthy(inputs[0].Constant),
            SemanticBranchPredicate.False => Truthy(inputs[0].Constant) is { } truth ? !truth : null,
            SemanticBranchPredicate.Equal => Equal(inputs[0].Constant, inputs[1].Constant),
            SemanticBranchPredicate.NotEqual => CompareBranch(semantic.Semantics,
                inputs[0].Constant, inputs[1].Constant, SemanticBranchPredicate.NotEqual),
            SemanticBranchPredicate.GreaterThan or SemanticBranchPredicate.GreaterThanOrEqual
                or SemanticBranchPredicate.LessThan or SemanticBranchPredicate.LessThanOrEqual =>
                CompareBranch(semantic.Semantics, inputs[0].Constant, inputs[1].Constant,
                    semantic.Semantics.Predicate),
            _ => null,
        };
        return taken is { } known
            ? new SccpTerminatorDecision(true, known)
            : default;
    }

    private static bool TryFoldPureCall(
        SemanticOperation operation,
        IReadOnlyList<object?> inputs,
        out object? result)
    {
        result = null;
        if (operation.Operand is not IMethodDescriptor method
            || method.DeclaringType?.FullName != "System.Math"
            || method.Name?.ToString() != "Abs" || inputs.Count != 1)
            return false;
        result = inputs[0] switch
        {
            int value => Math.Abs(value),
            long value => Math.Abs(value),
            short value => Math.Abs(value),
            sbyte value => Math.Abs(value),
            float value => Math.Abs(value),
            double value => Math.Abs(value),
            _ => null,
        };
        return inputs[0] is int or long or short or sbyte or float or double;
    }

    private static bool TryBinary(
        SemanticOperation operation,
        IReadOnlyList<object?> inputs,
        AbstractValue outputType,
        out object? result)
    {
        result = null;
        if (inputs.Count != 2)
            return false;
        if (outputType.Kind is AbstractValueKind.Float32 or AbstractValueKind.Float64)
        {
            if (!TryDouble(inputs[0], out double left) || !TryDouble(inputs[1], out double right))
                return false;
            double value = operation.Code switch
            {
                SemanticOperationCode.Add => left + right,
                SemanticOperationCode.Subtract => left - right,
                SemanticOperationCode.Multiply => left * right,
                SemanticOperationCode.Divide => left / right,
                SemanticOperationCode.Remainder => left % right,
                _ => double.NaN,
            };
            if (double.IsNaN(value) && operation.Code is not SemanticOperationCode.Divide
                and not SemanticOperationCode.Remainder)
                return false;
            result = outputType.Kind == AbstractValueKind.Float32 ? (float)value : value;
            return true;
        }
        if (!TryInt64(inputs[0], out long signedLeft)
            || !TryInt64(inputs[1], out long signedRight))
            return false;
        bool int32 = outputType.Kind == AbstractValueKind.Int32;
        int shift = unchecked((int)signedRight);
        if (operation.Semantics.Overflow == SemanticOverflowMode.Checked)
        {
            result = CheckedArithmetic(operation, signedLeft, signedRight, int32);
            return true;
        }
        if (operation.Semantics.Signedness == SemanticSignedness.Unsigned
            && operation.Code is SemanticOperationCode.Divide or SemanticOperationCode.Remainder
                or SemanticOperationCode.ShiftRight)
        {
            ulong left = int32 ? unchecked((uint)signedLeft) : unchecked((ulong)signedLeft);
            ulong right = int32 ? unchecked((uint)signedRight) : unchecked((ulong)signedRight);
            if (right == 0 && operation.Code is SemanticOperationCode.Divide
                or SemanticOperationCode.Remainder)
                return false;
            ulong unsignedValue = operation.Code switch
            {
                SemanticOperationCode.Divide => left / right,
                SemanticOperationCode.Remainder => left % right,
                SemanticOperationCode.ShiftRight => left >> shift,
                _ => 0,
            };
            result = int32 ? unchecked((int)(uint)unsignedValue) : unchecked((long)unsignedValue);
            return true;
        }
        if (signedRight == 0 && operation.Code is SemanticOperationCode.Divide
            or SemanticOperationCode.Remainder)
            return false;
        long signedValue = operation.Code switch
        {
            SemanticOperationCode.Add => signedLeft + signedRight,
            SemanticOperationCode.Subtract => signedLeft - signedRight,
            SemanticOperationCode.Multiply => signedLeft * signedRight,
            SemanticOperationCode.Divide => signedLeft / signedRight,
            SemanticOperationCode.Remainder => signedLeft % signedRight,
            SemanticOperationCode.BitwiseAnd => signedLeft & signedRight,
            SemanticOperationCode.BitwiseOr => signedLeft | signedRight,
            SemanticOperationCode.BitwiseXor => signedLeft ^ signedRight,
            SemanticOperationCode.ShiftLeft => signedLeft << shift,
            SemanticOperationCode.ShiftRight => signedLeft >> shift,
            _ => 0,
        };
        result = int32 ? unchecked((int)signedValue) : signedValue;
        return true;
    }

    private static object CheckedArithmetic(
        SemanticOperation operation,
        long left,
        long right,
        bool int32)
    {
        bool unsigned = operation.Semantics.Signedness == SemanticSignedness.Unsigned;
        if (unsigned && int32)
        {
            uint a = checked((uint)left);
            uint b = checked((uint)right);
            uint value = operation.Code switch
            {
                SemanticOperationCode.Add => checked(a + b),
                SemanticOperationCode.Subtract => checked(a - b),
                SemanticOperationCode.Multiply => checked(a * b),
                _ => throw new ArithmeticException(),
            };
            return unchecked((int)value);
        }
        if (unsigned)
        {
            ulong a = checked((ulong)left);
            ulong b = checked((ulong)right);
            ulong value = operation.Code switch
            {
                SemanticOperationCode.Add => checked(a + b),
                SemanticOperationCode.Subtract => checked(a - b),
                SemanticOperationCode.Multiply => checked(a * b),
                _ => throw new ArithmeticException(),
            };
            return unchecked((long)value);
        }
        if (int32)
        {
            int a = checked((int)left);
            int b = checked((int)right);
            return operation.Code switch
            {
                SemanticOperationCode.Add => checked(a + b),
                SemanticOperationCode.Subtract => checked(a - b),
                SemanticOperationCode.Multiply => checked(a * b),
                _ => throw new ArithmeticException(),
            };
        }
        return operation.Code switch
        {
            SemanticOperationCode.Add => checked(left + right),
            SemanticOperationCode.Subtract => checked(left - right),
            SemanticOperationCode.Multiply => checked(left * right),
            _ => throw new ArithmeticException(),
        };
    }

    private static bool TryUnary(
        SemanticOperationCode code,
        object? input,
        AbstractValue outputType,
        out object? result)
    {
        result = null;
        if (outputType.Kind is AbstractValueKind.Float32 or AbstractValueKind.Float64)
        {
            if (code != SemanticOperationCode.Negate || !TryDouble(input, out double number))
                return false;
            result = outputType.Kind == AbstractValueKind.Float32 ? (float)-number : -number;
            return true;
        }
        if (!TryInt64(input, out long value))
            return false;
        long folded = code == SemanticOperationCode.Negate ? -value : ~value;
        result = outputType.Kind == AbstractValueKind.Int32 ? unchecked((int)folded) : folded;
        return true;
    }

    private static bool TryCompare(
        SemanticOperation operation,
        object? left,
        object? right,
        out bool result)
    {
        result = false;
        if (operation.Code == SemanticOperationCode.CompareEqual)
        {
            bool? equal = Equal(left, right);
            if (equal is null)
                return false;
            result = equal.Value;
            return true;
        }
        var predicate = operation.Code == SemanticOperationCode.CompareLessThan
            ? SemanticBranchPredicate.LessThan : SemanticBranchPredicate.GreaterThan;
        bool? comparison = CompareBranch(
            new SemanticTerminatorSemantics(predicate, operation.Semantics.Signedness,
                UnorderedFloatingPoint: operation.Semantics.UnorderedFloatingPoint),
            left, right, predicate);
        if (comparison is null)
            return false;
        result = comparison.Value;
        return true;
    }

    private static bool TryConvert(
        SemanticInstructionSemantics semantics,
        object? input,
        out object? result)
    {
        result = null;
        if (!TryDouble(input, out double number))
            return false;
        bool checkedMode = semantics.Overflow == SemanticOverflowMode.Checked;
        result = semantics.PrimitiveType switch
        {
            SemanticPrimitiveType.Int8 => checkedMode ? checked((sbyte)number) : unchecked((sbyte)number),
            SemanticPrimitiveType.UInt8 => checkedMode ? checked((byte)number) : unchecked((byte)number),
            SemanticPrimitiveType.Int16 => checkedMode ? checked((short)number) : unchecked((short)number),
            SemanticPrimitiveType.UInt16 => checkedMode ? checked((ushort)number) : unchecked((ushort)number),
            SemanticPrimitiveType.Int32 => checkedMode ? checked((int)number) : unchecked((int)number),
            SemanticPrimitiveType.UInt32 => checkedMode ? checked((uint)number) : unchecked((uint)number),
            SemanticPrimitiveType.Int64 => checkedMode ? checked((long)number) : unchecked((long)number),
            SemanticPrimitiveType.UInt64 => checkedMode ? checked((ulong)number) : unchecked((ulong)number),
            SemanticPrimitiveType.NativeInt => checkedMode ? checked((long)number) : unchecked((long)number),
            SemanticPrimitiveType.NativeUInt => checkedMode ? checked((ulong)number) : unchecked((ulong)number),
            SemanticPrimitiveType.Float32 => (float)number,
            SemanticPrimitiveType.Float64 => number,
            _ => null,
        };
        return result is not null;
    }

    private static bool? CompareBranch(
        SemanticTerminatorSemantics semantics,
        object? left,
        object? right,
        SemanticBranchPredicate predicate)
    {
        if (TryDouble(left, out double floatingLeft)
            && TryDouble(right, out double floatingRight)
            && (left is float or double || right is float or double))
        {
            bool unordered = double.IsNaN(floatingLeft) || double.IsNaN(floatingRight);
            if (unordered)
                return semantics.UnorderedFloatingPoint;
            return predicate switch
            {
                SemanticBranchPredicate.NotEqual => floatingLeft != floatingRight,
                SemanticBranchPredicate.GreaterThan => floatingLeft > floatingRight,
                SemanticBranchPredicate.GreaterThanOrEqual => floatingLeft >= floatingRight,
                SemanticBranchPredicate.LessThan => floatingLeft < floatingRight,
                SemanticBranchPredicate.LessThanOrEqual => floatingLeft <= floatingRight,
                _ => null,
            };
        }
        if (!TryInt64(left, out long signedLeft) || !TryInt64(right, out long signedRight))
            return predicate == SemanticBranchPredicate.NotEqual ? Negate(Equal(left, right)) : null;
        if (predicate == SemanticBranchPredicate.NotEqual)
            return signedLeft != signedRight;
        if (semantics.Signedness == SemanticSignedness.Unsigned)
        {
            ulong a = unchecked((ulong)signedLeft);
            ulong b = unchecked((ulong)signedRight);
            return predicate switch
            {
                SemanticBranchPredicate.GreaterThan => a > b,
                SemanticBranchPredicate.GreaterThanOrEqual => a >= b,
                SemanticBranchPredicate.LessThan => a < b,
                SemanticBranchPredicate.LessThanOrEqual => a <= b,
                _ => null,
            };
        }
        return predicate switch
        {
            SemanticBranchPredicate.GreaterThan => signedLeft > signedRight,
            SemanticBranchPredicate.GreaterThanOrEqual => signedLeft >= signedRight,
            SemanticBranchPredicate.LessThan => signedLeft < signedRight,
            SemanticBranchPredicate.LessThanOrEqual => signedLeft <= signedRight,
            _ => null,
        };
    }

    private static bool? Truthy(object? value)
    {
        if (value is null)
            return false;
        if (TryInt64(value, out long number))
            return number != 0;
        if (value is string)
            return true;
        return null;
    }

    private static bool? Equal(object? left, object? right)
    {
        if (left is null || right is null)
            return left is null && right is null;
        if (TryDouble(left, out double a) && TryDouble(right, out double b))
            return a == b;
        return left.GetType().IsValueType && right.GetType().IsValueType
            ? Equals(left, right) : null;
    }

    private static bool? Negate(bool? value) => value is { } known ? !known : null;

    private static bool TryDouble(object? value, out double number)
    {
        if (value is byte or sbyte or short or ushort or int or uint or long or ulong
            or char or float or double)
        {
            number = Convert.ToDouble(value);
            return true;
        }
        number = 0;
        return false;
    }

    private static bool TryInt64(object? value, out long number)
    {
        if (value is bool boolean)
        {
            number = boolean ? 1 : 0;
            return true;
        }
        if (value is byte or sbyte or short or ushort or int or uint or long or char)
        {
            number = Convert.ToInt64(value);
            return true;
        }
        number = 0;
        return false;
    }
}
