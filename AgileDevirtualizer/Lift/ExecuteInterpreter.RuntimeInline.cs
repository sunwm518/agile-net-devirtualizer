using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Transactional symbolic inliner for VM-runtime stack helpers. Unlike signature/name heuristics,
/// this follows the helper's concrete CFG and commits only after a fully understood path reaches
/// ret. It reconstructs conversions and arithmetic on the already-materialised program values while
/// erasing boxed-wrapper metadata plumbing.
/// </summary>
internal sealed partial class ExecuteInterpreter
{
    private bool TryInlineRuntimeStackHelper(IMethodDescriptor method, SymValue[] args)
    {
        MethodDefinition? definition;
        try { definition = method.Resolve(_ctx); }
        catch { return false; }
        if (definition is not { IsStatic: true, CilMethodBody: not null }
            || !ReferenceEquals(definition.DeclaringModule, _vocab.ValueType.DeclaringModule))
            return false;

        int live = args.Count(IsStack);
        bool candidate = live == 0 || (live > 0 && definition.Signature?.ReturnType.IsTypeOf("System", "Object") == true);
        if (!candidate)
            return false;

        var active = new HashSet<MethodDefinition>();
        if (!TryRunRuntimeHelper(definition, args, active, depth: 0, out var result, out var emitted))
            return false;

        _out.AddRange(emitted);
        if (result is not SymValue.Void)
            _eval.Push(result);
        return true;
    }

    private bool TryRunRuntimeHelper(MethodDefinition method, SymValue[] args, HashSet<MethodDefinition> active,
                                     int depth, out SymValue result, out List<LiftedOp> emitted)
    {
        result = new SymValue.Unknown("runtime-inline-failed");
        emitted = [];
        if (depth > 8 || method.CilMethodBody is not { } body || !active.Add(method))
            return false;

        try
        {
            var instructions = body.Instructions;
            instructions.CalculateOffsets();
            var offsets = new Dictionary<int, int>();
            for (int i = 0; i < instructions.Count; i++)
                offsets[(int)instructions[i].Offset] = i;

            var stack = new Stack<SymValue>();
            var locals = new Dictionary<int, SymValue>();
            int ip = 0;
            for (int guard = 0; ip >= 0 && ip < instructions.Count && guard < 10000; guard++)
            {
                var instruction = instructions[ip];
                int next = ip + 1;
                switch (instruction.OpCode.Code)
                {
                    case CilCode.Nop:
                    case CilCode.Box:
                    case CilCode.Unbox:
                        break;

                    case CilCode.Ldarg_0: stack.Push(args.ElementAtOrDefault(0) ?? new SymValue.Unknown("arg0")); break;
                    case CilCode.Ldarg_1: stack.Push(args.ElementAtOrDefault(1) ?? new SymValue.Unknown("arg1")); break;
                    case CilCode.Ldarg_2: stack.Push(args.ElementAtOrDefault(2) ?? new SymValue.Unknown("arg2")); break;
                    case CilCode.Ldarg_3: stack.Push(args.ElementAtOrDefault(3) ?? new SymValue.Unknown("arg3")); break;
                    case CilCode.Ldarg:
                    case CilCode.Ldarg_S:
                        stack.Push(args.ElementAtOrDefault(ArgIndex(instruction)) ?? new SymValue.Unknown("arg"));
                        break;

                    case CilCode.Ldloc_0: stack.Push(locals.GetValueOrDefault(0, new SymValue.Unknown("local0"))); break;
                    case CilCode.Ldloc_1: stack.Push(locals.GetValueOrDefault(1, new SymValue.Unknown("local1"))); break;
                    case CilCode.Ldloc_2: stack.Push(locals.GetValueOrDefault(2, new SymValue.Unknown("local2"))); break;
                    case CilCode.Ldloc_3: stack.Push(locals.GetValueOrDefault(3, new SymValue.Unknown("local3"))); break;
                    case CilCode.Ldloc:
                    case CilCode.Ldloc_S:
                        stack.Push(locals.GetValueOrDefault(LocalIndex(instruction), new SymValue.Unknown("local")));
                        break;
                    case CilCode.Stloc_0: if (!TryPop(stack, out var st0)) return false; locals[0] = st0; break;
                    case CilCode.Stloc_1: if (!TryPop(stack, out var st1)) return false; locals[1] = st1; break;
                    case CilCode.Stloc_2: if (!TryPop(stack, out var st2)) return false; locals[2] = st2; break;
                    case CilCode.Stloc_3: if (!TryPop(stack, out var st3)) return false; locals[3] = st3; break;
                    case CilCode.Stloc:
                    case CilCode.Stloc_S:
                        if (!TryPop(stack, out var stored)) return false;
                        locals[LocalIndex(instruction)] = stored;
                        break;

                    case CilCode.Ldc_I4_M1: stack.Push(new SymValue.Operand(-1)); break;
                    case CilCode.Ldc_I4_0: stack.Push(new SymValue.Operand(0)); break;
                    case CilCode.Ldc_I4_1: stack.Push(new SymValue.Operand(1)); break;
                    case CilCode.Ldc_I4_2: stack.Push(new SymValue.Operand(2)); break;
                    case CilCode.Ldc_I4_3: stack.Push(new SymValue.Operand(3)); break;
                    case CilCode.Ldc_I4_4: stack.Push(new SymValue.Operand(4)); break;
                    case CilCode.Ldc_I4_5: stack.Push(new SymValue.Operand(5)); break;
                    case CilCode.Ldc_I4_6: stack.Push(new SymValue.Operand(6)); break;
                    case CilCode.Ldc_I4_7: stack.Push(new SymValue.Operand(7)); break;
                    case CilCode.Ldc_I4_8: stack.Push(new SymValue.Operand(8)); break;
                    case CilCode.Ldc_I4:
                    case CilCode.Ldc_I4_S: stack.Push(new SymValue.Operand(Convert.ToInt32(instruction.Operand))); break;
                    case CilCode.Ldc_I8: stack.Push(new SymValue.Operand(Convert.ToInt64(instruction.Operand))); break;
                    case CilCode.Ldnull: stack.Push(new SymValue.Operand(null)); break;
                    case CilCode.Dup:
                        if (stack.Count == 0) return false;
                        stack.Push(stack.Peek());
                        break;
                    case CilCode.Pop:
                        if (stack.Count == 0) return false;
                        stack.Pop();
                        break;

                    case CilCode.Isinst:
                        if (!TryPop(stack, out var tested) || instruction.Operand is not ITypeDefOrRef wanted)
                            return false;
                        stack.Push(RuntimeTypeMatches(tested, wanted) ? tested : new SymValue.Operand(null));
                        break;
                    case CilCode.Unbox_Any:
                    case CilCode.Castclass:
                        if (!TryPop(stack, out var castValue) || instruction.Operand is not ITypeDefOrRef castType)
                            return false;
                        stack.Push(WithKnownType(castValue, TypeSignatureOf(castType)));
                        break;

                    case CilCode.Conv_I:
                    case CilCode.Conv_U:
                    case CilCode.Conv_I4:
                    case CilCode.Conv_U4:
                    case CilCode.Conv_I8:
                    case CilCode.Conv_U8:
                        if (!TryPop(stack, out var converted)
                            || !TryInlineConversion(instruction.OpCode, converted, emitted, out var conversionResult))
                            return false;
                        stack.Push(conversionResult);
                        break;

                    case CilCode.Add:
                    case CilCode.Add_Ovf:
                    case CilCode.Add_Ovf_Un:
                    case CilCode.Sub:
                    case CilCode.Sub_Ovf:
                    case CilCode.Sub_Ovf_Un:
                    case CilCode.Mul:
                    case CilCode.Mul_Ovf:
                    case CilCode.Mul_Ovf_Un:
                    case CilCode.Div:
                    case CilCode.Div_Un:
                    case CilCode.Rem:
                    case CilCode.Rem_Un:
                    case CilCode.And:
                    case CilCode.Or:
                    case CilCode.Xor:
                    case CilCode.Shl:
                    case CilCode.Shr:
                    case CilCode.Shr_Un:
                        if (!TryPop(stack, out var right) || !TryPop(stack, out var left)
                            || !TryInlineBinary(instruction.OpCode, left, right, emitted, out var binaryResult))
                            return false;
                        stack.Push(binaryResult);
                        break;

                    case CilCode.Ceq:
                        if (!TryPop(stack, out var eqRight) || !TryPop(stack, out var eqLeft)
                            || !TryConstEq(eqLeft, eqRight, out bool equal))
                            return false;
                        stack.Push(new SymValue.Operand(equal ? 1 : 0));
                        break;
                    case CilCode.Cgt:
                    case CilCode.Cgt_Un:
                    case CilCode.Clt:
                    case CilCode.Clt_Un:
                        if (!TryPop(stack, out var orderRight) || !TryPop(stack, out var orderLeft))
                            return false;
                        bool ordered;
                        if (TryLong(orderLeft, out long orderA) && TryLong(orderRight, out long orderB))
                            ordered = instruction.OpCode.Code is CilCode.Cgt or CilCode.Cgt_Un ? orderA > orderB : orderA < orderB;
                        else if (!TryNullCheck(instruction.OpCode.Code, orderLeft, orderRight, out ordered))
                            return false;
                        stack.Push(new SymValue.Operand(ordered ? 1 : 0));
                        break;

                    case CilCode.Br:
                    case CilCode.Br_S:
                        if (!TryInlineTarget(instruction, offsets, out next)) return false;
                        break;
                    case CilCode.Brtrue:
                    case CilCode.Brtrue_S:
                    case CilCode.Brfalse:
                    case CilCode.Brfalse_S:
                        if (!TryPop(stack, out var condition) || !TryConstBool(condition, out bool truth)
                            || !TryInlineTarget(instruction, offsets, out int branchTarget))
                            return false;
                        bool branchOnTrue = instruction.OpCode.Code is CilCode.Brtrue or CilCode.Brtrue_S;
                        if (truth == branchOnTrue) next = branchTarget;
                        break;
                    case CilCode.Beq:
                    case CilCode.Beq_S:
                    case CilCode.Bne_Un:
                    case CilCode.Bne_Un_S:
                        if (!TryPop(stack, out var compareRight) || !TryPop(stack, out var compareLeft)
                            || !TryConstEq(compareLeft, compareRight, out bool areEqual)
                            || !TryInlineTarget(instruction, offsets, out int equalityTarget))
                            return false;
                        bool branchWhenEqual = instruction.OpCode.Code is CilCode.Beq or CilCode.Beq_S;
                        if (areEqual == branchWhenEqual) next = equalityTarget;
                        break;
                    case CilCode.Blt:
                    case CilCode.Blt_S:
                    case CilCode.Blt_Un:
                    case CilCode.Blt_Un_S:
                    case CilCode.Ble:
                    case CilCode.Ble_S:
                    case CilCode.Ble_Un:
                    case CilCode.Ble_Un_S:
                    case CilCode.Bgt:
                    case CilCode.Bgt_S:
                    case CilCode.Bgt_Un:
                    case CilCode.Bgt_Un_S:
                    case CilCode.Bge:
                    case CilCode.Bge_S:
                    case CilCode.Bge_Un:
                    case CilCode.Bge_Un_S:
                        if (!TryPop(stack, out var relationRight) || !TryPop(stack, out var relationLeft)
                            || !TryLong(relationLeft, out long relationA) || !TryLong(relationRight, out long relationB)
                            || !TryInlineTarget(instruction, offsets, out int relationTarget))
                            return false;
                        bool takeRelation = instruction.OpCode.Code switch
                        {
                            CilCode.Blt or CilCode.Blt_S or CilCode.Blt_Un or CilCode.Blt_Un_S => relationA < relationB,
                            CilCode.Ble or CilCode.Ble_S or CilCode.Ble_Un or CilCode.Ble_Un_S => relationA <= relationB,
                            CilCode.Bgt or CilCode.Bgt_S or CilCode.Bgt_Un or CilCode.Bgt_Un_S => relationA > relationB,
                            _ => relationA >= relationB,
                        };
                        if (takeRelation) next = relationTarget;
                        break;
                    case CilCode.Switch:
                        if (!TryPop(stack, out var selector) || !TryInt(selector, out int selected)
                            || instruction.Operand is not IList<ICilLabel> labels)
                            return false;
                        if (selected >= 0 && selected < labels.Count
                            && !offsets.TryGetValue((int)labels[selected].Offset, out next))
                            return false;
                        break;

                    case CilCode.Call:
                    case CilCode.Callvirt:
                        if (instruction.Operand is not IMethodDescriptor called
                            || !TryInlineCall(called, stack, active, depth, emitted, out var callResult))
                            return false;
                        if (callResult is not SymValue.Void)
                            stack.Push(callResult);
                        break;

                    case CilCode.Newobj:
                        if (instruction.Operand is not IMethodDescriptor constructor
                            || !TryInlineNewObj(constructor, stack, emitted, out var newValue))
                            return false;
                        stack.Push(newValue);
                        break;

                    case CilCode.Ret:
                        result = stack.Count > 0 ? stack.Pop() : new SymValue.Void();
                        return result is not SymValue.Unknown;

                    default:
                        TraceRuntimeInline($"{method} stopped at IL_{instruction.Offset:X4}: {instruction.OpCode.Code}");
                        return false;
                }
                ip = next;
            }
            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            active.Remove(method);
        }
    }

    private bool TryInlineCall(IMethodDescriptor called, Stack<SymValue> stack,
                               HashSet<MethodDefinition> active, int depth, List<LiftedOp> emitted,
                               out SymValue result)
    {
        result = new SymValue.Unknown("runtime-inline-call");
        int count = ParamCount(called) + (HasThis(called) ? 1 : 0);
        if (stack.Count < count)
            return false;
        var callArgs = new SymValue[count];
        for (int i = count - 1; i >= 0; i--)
            callArgs[i] = stack.Pop();

        MethodDefinition? definition;
        try { definition = called.Resolve(_ctx); }
        catch { return false; }
        if (definition is not null && ReferenceEquals(definition.DeclaringModule, _vocab.ValueType.DeclaringModule))
        {
            if (!TryRunRuntimeHelper(definition, callArgs, active, depth + 1, out result, out var nested))
                return false;
            emitted.AddRange(nested);
            return true;
        }

        string ns = called.DeclaringType?.Namespace?.ToString() ?? "";
        string type = called.DeclaringType?.Name?.ToString() ?? "";
        string name = called.Name?.ToString() ?? "";
        if (TryEvaluateRuntimeMetadataCall(ns, type, name, callArgs, out result))
            return true;
        if (ns == "System" && type == "Convert" && name.StartsWith("To", StringComparison.Ordinal)
            && callArgs.Length == 1 && ConversionForSystemType(name[2..]) is { } conversion)
            return TryInlineConversion(conversion, callArgs[0], emitted, out result);

        if (ns == "System" && type is "IntPtr" or "UIntPtr" && name == "get_Size")
        {
            result = new SymValue.Operand(IntPtr.Size);
            return true;
        }
        TraceRuntimeInline($"unmodelled nested call: {called}");
        return false;
    }

    private bool TryInlineNewObj(IMethodDescriptor constructor, Stack<SymValue> stack,
                                 List<LiftedOp> emitted, out SymValue result)
    {
        result = new SymValue.Unknown("runtime-inline-newobj");
        int count = ParamCount(constructor);
        if (stack.Count < count || count != 1)
            return false;
        var value = stack.Pop();
        string ns = constructor.DeclaringType?.Namespace?.ToString() ?? "";
        string type = constructor.DeclaringType?.Name?.ToString() ?? "";
        if (ns != "System" || type is not ("IntPtr" or "UIntPtr"))
            return false;
        var conversion = type == "IntPtr" ? CilOpCodes.Conv_I : CilOpCodes.Conv_U;
        return TryInlineConversion(conversion, value, emitted, out result);
    }

    private bool TryInlineConversion(CilOpCode conversion, SymValue value, List<LiftedOp> emitted,
                                     out SymValue result)
    {
        result = new SymValue.Unknown("runtime-inline-conv");
        if (value is SymValue.Operand { Value: { } constant } && IsIntLike(constant))
        {
            result = new SymValue.Operand(Convert.ToInt64(constant));
            return true;
        }
        if (value is not SymValue.OnStack { ManagedPointer: false })
            return false;
        emitted.Add(new LiftedOp(conversion));
        result = new SymValue.OnStack(TypeForConversion(conversion.Code));
        return true;
    }

    private bool TryInlineBinary(CilOpCode operation, SymValue left, SymValue right,
                                 List<LiftedOp> emitted, out SymValue result)
    {
        result = new SymValue.Unknown("runtime-inline-binary");
        if (TryLong(left, out long a) && TryLong(right, out long b))
        {
            try
            {
                result = new SymValue.Operand(operation.Code switch
                {
                    CilCode.Add or CilCode.Add_Ovf or CilCode.Add_Ovf_Un => a + b,
                    CilCode.Sub or CilCode.Sub_Ovf or CilCode.Sub_Ovf_Un => a - b,
                    CilCode.Mul or CilCode.Mul_Ovf or CilCode.Mul_Ovf_Un => a * b,
                    CilCode.Div or CilCode.Div_Un => a / b,
                    CilCode.Rem or CilCode.Rem_Un => a % b,
                    CilCode.And => a & b,
                    CilCode.Or => a | b,
                    CilCode.Xor => a ^ b,
                    CilCode.Shl => a << (int)b,
                    CilCode.Shr or CilCode.Shr_Un => a >> (int)b,
                    _ => throw new InvalidOperationException(),
                });
                return true;
            }
            catch { return false; }
        }
        if (left is not SymValue.OnStack || right is not SymValue.OnStack)
            return false;
        emitted.Add(new LiftedOp(NormalizeRuntimeBinaryOp(operation)));
        var leftCategory = StackComparisonCategoryOf(left);
        var rightCategory = StackComparisonCategoryOf(right);
        TypeSignature? resultType = NumericFamily(leftCategory) == 1 && NumericFamily(rightCategory) == 1
            ? _module.CorLibTypeFactory.Int32
            : KnownTypeOf(left) ?? KnownTypeOf(right);
        result = new SymValue.OnStack(resultType);
        return true;
    }

    private static CilOpCode NormalizeRuntimeBinaryOp(CilOpCode operation) => operation.Code switch
    {
        CilCode.Add_Ovf or CilCode.Add_Ovf_Un => CilOpCodes.Add,
        CilCode.Sub_Ovf or CilCode.Sub_Ovf_Un => CilOpCodes.Sub,
        CilCode.Mul_Ovf or CilCode.Mul_Ovf_Un => CilOpCodes.Mul,
        _ => operation,
    };

    private bool RuntimeTypeMatches(SymValue value, ITypeDefOrRef wanted)
    {
        var actual = KnownTypeOf(value);
        var target = TypeSignatureOf(wanted);
        if (actual is null || target is null)
            return false;
        if (actual.FullName == target.FullName)
            return true;
        // The VM normalises all CLR I4-stack values (small integers, Boolean, Char, and matching
        // enums) to its Int32 arithmetic path. Native CIL already carries those values as I4, so
        // following that path symbolically lets the helper collapse to the original arithmetic op.
        return target.IsTypeOf("System", "Int32")
            && NumericFamily(StackComparisonCategoryOf(value)) == 1;
    }

    private static SymValue WithKnownType(SymValue value, TypeSignature? type) => value switch
    {
        SymValue.OnStack onStack => onStack with { KnownType = type ?? onStack.KnownType },
        _ => value,
    };

    private TypeSignature? TypeForConversion(CilCode code) => code switch
    {
        CilCode.Conv_I4 or CilCode.Conv_U4 => _module.CorLibTypeFactory.Int32,
        CilCode.Conv_I8 or CilCode.Conv_U8 => _module.CorLibTypeFactory.Int64,
        CilCode.Conv_I => _module.CorLibTypeFactory.IntPtr,
        CilCode.Conv_U => _module.CorLibTypeFactory.UIntPtr,
        _ => null,
    };

    private static CilOpCode? ConversionForSystemType(string name) => name switch
    {
        "Int32" => CilOpCodes.Conv_I4,
        "UInt32" => CilOpCodes.Conv_U4,
        "Int64" => CilOpCodes.Conv_I8,
        "UInt64" => CilOpCodes.Conv_U8,
        _ => null,
    };

    private static bool TryInlineTarget(CilInstruction instruction, Dictionary<int, int> offsets, out int target)
    {
        target = -1;
        return instruction.Operand is ICilLabel label && offsets.TryGetValue((int)label.Offset, out target);
    }

    private static bool TryPop(Stack<SymValue> stack, out SymValue value)
    {
        if (stack.Count == 0)
        {
            value = new SymValue.Unknown("runtime-inline-underflow");
            return false;
        }
        value = stack.Pop();
        return true;
    }

    private static void TraceRuntimeInline(string message)
    {
        if (Environment.GetEnvironmentVariable("DBG_RUNTIME_INLINE") == "1")
            Console.Error.WriteLine($"[runtime-inline] {message}");
    }
}
