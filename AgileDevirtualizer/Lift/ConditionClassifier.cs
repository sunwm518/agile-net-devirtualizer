using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

/// <summary>
/// Identifies the VM's comparison-primitive helpers (is-zero / eq / lt / gt / le / ge) by probing:
/// each candidate is a static bool-returning method taking one or two comparable operands, which we
/// concretely interpret with a few integer inputs and classify from the resulting truth table. No
/// method name is trusted — a build can rename or reshuffle these freely.
/// </summary>
internal sealed class ConditionClassifier
{
    private readonly Dictionary<MethodDefinition, Relation?> _cache = new();
    private readonly RuntimeContext? _ctx;

    private ConditionClassifier(RuntimeContext? ctx) => _ctx = ctx;

    public static ConditionClassifier Build(Runtime.RuntimeModel runtime) => new(runtime.Module.RuntimeContext);

    /// <summary>The relation a call target computes, or null if it is not a comparison primitive.</summary>
    public Relation? Relation(IMethodDescriptor? m)
    {
        MethodDefinition? def;
        try { def = m?.Resolve(_ctx); } catch { return null; }
        if (def is null) return null;
        if (_cache.TryGetValue(def, out var cached)) return cached;
        _cache[def] = null; // guard re-entrancy
        return _cache[def] = Classify(def);
    }

    private static Relation? Classify(MethodDefinition def)
    {
        if (def is not { IsStatic: true } || def.Signature is not { } sig
            || !(sig.ReturnType?.IsTypeOf("System", "Boolean") ?? false)
            || def.CilMethodBody is null)
            return null;

        int operands = LeadingOperandCount(sig);
        if (operands == 1)
        {
            var t0 = Probe(def, Box(0));
            var t1 = Probe(def, Box(1));
            return t0 == true && t1 == false ? Lift.Relation.Falsy : null;
        }
        if (operands >= 2)
        {
            var lt = Probe(def, Box(0), Box(1)); // a<b
            var gt = Probe(def, Box(1), Box(0)); // a>b
            var eq = Probe(def, Box(1), Box(1)); // a==b
            if (lt is null || gt is null || eq is null) return null;
            return (lt, gt, eq) switch
            {
                (true, false, false) => Lift.Relation.Lt,
                (false, true, false) => Lift.Relation.Gt,
                (true, false, true) => Lift.Relation.Le,
                (false, true, true) => Lift.Relation.Ge,
                (false, false, true) => Lift.Relation.Eq,
                (true, true, false) => Lift.Relation.Ne,
                _ => null,
            };
        }
        return null;
    }

    /// <summary>How many leading parameters are the comparable operands (object/primitive, not an enum flag).</summary>
    private static int LeadingOperandCount(MethodSignature sig)
    {
        int n = 0;
        foreach (var p in sig.ParameterTypes)
        {
            bool comparable = p.IsTypeOf("System", "Object") || p.IsTypeOf("System", "Int32")
                || p.IsTypeOf("System", "Int64") || p.IsTypeOf("System", "IntPtr")
                || p.IsTypeOf("System", "UInt32") || p.IsTypeOf("System", "UInt64")
                || p.IsTypeOf("System", "Single") || p.IsTypeOf("System", "Double");
            if (!comparable) break;
            n++;
        }
        return n;
    }

    private static object Box(int v) => v;

    /// <summary>Concretely interprets the helper on boxed-int inputs; returns its bool result or null.</summary>
    private static bool? Probe(MethodDefinition def, params object?[] operands)
    {
        var instrs = def.CilMethodBody!.Instructions;
        instrs.CalculateOffsets();
        var map = new Dictionary<int, int>();
        for (int i = 0; i < instrs.Count; i++) map[(int)instrs[i].Offset] = i;

        // Arguments: the comparable operands, remaining params default to 0 (e.g. an ordering-mode enum).
        int argc = def.Signature!.ParameterTypes.Count;
        var args = new object?[argc];
        for (int i = 0; i < argc; i++) args[i] = i < operands.Length ? operands[i] : 0;

        var stack = new Stack<object?>();
        var locals = new Dictionary<int, object?>();
        int ip = 0, guard = 0;
        try
        {
            while (ip >= 0 && ip < instrs.Count && guard++ < 5000)
            {
                var c = instrs[ip];
                int next = ip + 1;
                switch (c.OpCode.Code)
                {
                    case CilCode.Nop: case CilCode.Box: break;
                    case CilCode.Ldloc_0: stack.Push(locals.GetValueOrDefault(0)); break;
                    case CilCode.Ldloc_1: stack.Push(locals.GetValueOrDefault(1)); break;
                    case CilCode.Ldloc_2: stack.Push(locals.GetValueOrDefault(2)); break;
                    case CilCode.Ldloc_3: stack.Push(locals.GetValueOrDefault(3)); break;
                    case CilCode.Ldloc: case CilCode.Ldloc_S:
                        stack.Push(locals.GetValueOrDefault(((CilLocalVariable)c.Operand!).Index)); break;
                    case CilCode.Stloc_0: locals[0] = stack.Pop(); break;
                    case CilCode.Stloc_1: locals[1] = stack.Pop(); break;
                    case CilCode.Stloc_2: locals[2] = stack.Pop(); break;
                    case CilCode.Stloc_3: locals[3] = stack.Pop(); break;
                    case CilCode.Stloc: case CilCode.Stloc_S:
                        locals[((CilLocalVariable)c.Operand!).Index] = stack.Pop(); break;
                    case CilCode.Ldarg_0: stack.Push(args.ElementAtOrDefault(0)); break;
                    case CilCode.Ldarg_1: stack.Push(args.ElementAtOrDefault(1)); break;
                    case CilCode.Ldarg_2: stack.Push(args.ElementAtOrDefault(2)); break;
                    case CilCode.Ldarg_3: stack.Push(args.ElementAtOrDefault(3)); break;
                    case CilCode.Ldarg: case CilCode.Ldarg_S:
                        stack.Push(args.ElementAtOrDefault(((Parameter)c.Operand!).Index)); break;
                    case CilCode.Ldc_I4_M1: stack.Push(-1); break;
                    case CilCode.Ldc_I4_0: stack.Push(0); break;
                    case CilCode.Ldc_I4_1: stack.Push(1); break;
                    case CilCode.Ldc_I4_S: case CilCode.Ldc_I4: stack.Push(Convert.ToInt32(c.Operand)); break;
                    case CilCode.Ldnull: stack.Push(null); break;
                    case CilCode.Dup: stack.Push(stack.Peek()); break;
                    case CilCode.Pop: stack.Pop(); break;
                    case CilCode.Isinst:
                        stack.Push(MatchesType(stack.Pop(), c.Operand as ITypeDefOrRef) ? (object)1 : null);
                        break;
                    case CilCode.Unbox_Any: case CilCode.Unbox: break; // boxed int already usable
                    case CilCode.Conv_I4: case CilCode.Conv_I8: case CilCode.Conv_I:
                    case CilCode.Conv_U4: case CilCode.Conv_U8: break;
                    case CilCode.Ceq: { long b = L(stack.Pop()); long a = L(stack.Pop()); stack.Push(a == b ? 1 : 0); break; }
                    case CilCode.Clt: case CilCode.Clt_Un: { long b = L(stack.Pop()); long a = L(stack.Pop()); stack.Push(a < b ? 1 : 0); break; }
                    case CilCode.Cgt: case CilCode.Cgt_Un: { long b = L(stack.Pop()); long a = L(stack.Pop()); stack.Push(a > b ? 1 : 0); break; }
                    case CilCode.Br: case CilCode.Br_S: next = map[(int)((ICilLabel)c.Operand!).Offset]; break;
                    case CilCode.Brtrue: case CilCode.Brtrue_S: if (B(stack.Pop())) next = map[(int)((ICilLabel)c.Operand!).Offset]; break;
                    case CilCode.Brfalse: case CilCode.Brfalse_S: if (!B(stack.Pop())) next = map[(int)((ICilLabel)c.Operand!).Offset]; break;
                    case CilCode.Ret: return B(stack.Count > 0 ? stack.Pop() : 0);
                    default: return null; // hit an unmodelled path — not a plain comparison we can probe
                }
                ip = next;
            }
        }
        catch { return null; }
        return null;
    }

    private static bool MatchesType(object? value, ITypeDefOrRef? type) =>
        value is int && (type?.Name?.ToString() == "Int32");

    private static long L(object? v) => v is null ? 0 : Convert.ToInt64(v);
    private static bool B(object? v) => v is not null && Convert.ToInt64(v) != 0;
}
