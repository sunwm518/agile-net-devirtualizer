using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.DotNet.Serialized;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata;
using System.Runtime.CompilerServices;

namespace AgileDevirtualizer.Decode;

/// <summary>
/// Decodes a handler's operands by <em>interpreting its real read-method IL</em> against the
/// live operand blob. Because the interpreter drives the actual <see cref="BinaryReader"/>, the
/// blob is consumed byte-for-byte exactly as the runtime would, and every value the method stores
/// into one of its fields is captured under that field's name. No operand layout is hardcoded.
/// </summary>
internal static partial class OperandDecoder
{
    private sealed class ThisRef { public static readonly ThisRef Instance = new(); }
    private sealed class ReaderRef { public static readonly ReaderRef Instance = new(); }
    private sealed class UserStringIndex(Dictionary<string, uint> lastOffsets, uint nextOffset)
    {
        private readonly Dictionary<string, uint> _lastOffsets = lastOffsets;
        private readonly Dictionary<string, uint> _projectedOffsets = new(StringComparer.Ordinal);
        private uint _nextOffset = nextOffset;

        public uint RawTokenFor(string value)
        {
            lock (_projectedOffsets)
            {
                if (_lastOffsets.TryGetValue(value, out uint existing))
                    return 0x70000000u + existing;
                if (_projectedOffsets.TryGetValue(value, out uint projected))
                    return projected;

                // Mirror the preserving #US builder: unseen strings are appended in encounter
                // order. Once an entry would start above 0x00FFFFFF it cannot be represented by
                // ldstr, so leave the heap unchanged and request char[] materialisation instead.
                if (_nextOffset > 0x00FFFFFFu)
                    return _projectedOffsets[value] = uint.MaxValue;

                uint rawToken = 0x70000000u + _nextOffset;
                _projectedOffsets[value] = rawToken;
                _nextOffset = checked(_nextOffset + EncodedUserStringSize(value));
                return rawToken;
            }
        }

        private static uint EncodedUserStringSize(string value)
        {
            uint payload = checked((uint) value.Length * 2u + 1u);
            uint prefix = payload <= 0x7Fu ? 1u : payload <= 0x3FFFu ? 2u : 4u;
            return checked(prefix + payload);
        }
    }
    private static readonly ConditionalWeakTable<ModuleDefinition, UserStringIndex> UserStringsByModule = new();

    public static Dictionary<string, object?> Decode(ModuleDefinition module, HandlerInfo handler, BinaryReader reader)
    {
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        var body = handler.ReadMethod?.CilMethodBody;
        if (body is null)
            return fields; // handlers with no operands (e.g. nop) legitimately read nothing

        var instrs = body.Instructions;
        instrs.CalculateOffsets();
        var offsetToIndex = new Dictionary<int, int>();
        for (int i = 0; i < instrs.Count; i++)
            offsetToIndex[(int)instrs[i].Offset] = i;

        var stack = new Stack<object?>();
        var locals = new Dictionary<int, object?>();

        int ip = 0, guard = 0;
        while (ip >= 0 && ip < instrs.Count)
        {
            if (guard++ > 200_000)
                throw new InvalidDataException($"read-method {handler.ReadMethod!.Name} did not terminate");

            var instr = instrs[ip];
            int next = ip + 1;

            switch (instr.OpCode.Code)
            {
                case CilCode.Nop:
                case CilCode.Castclass:
                case CilCode.Conv_I:
                case CilCode.Conv_I1:
                case CilCode.Conv_I2:
                case CilCode.Conv_I4:
                case CilCode.Conv_I8:
                case CilCode.Conv_U:
                case CilCode.Conv_U1:
                case CilCode.Conv_U2:
                case CilCode.Conv_U4:
                case CilCode.Conv_U8:
                case CilCode.Conv_R4:
                case CilCode.Conv_R8:
                case CilCode.Box:
                case CilCode.Unbox_Any:
                    break;

                case CilCode.Ldarg_0: stack.Push(ThisRef.Instance); break;
                case CilCode.Ldarg_1: stack.Push(ReaderRef.Instance); break;
                case CilCode.Ldarg_2:
                case CilCode.Ldarg_3: stack.Push(null); break;
                case CilCode.Ldarg:
                case CilCode.Ldarg_S:
                    stack.Push(ArgIndex(instr) switch { 0 => ThisRef.Instance, 1 => ReaderRef.Instance, _ => null });
                    break;

                case CilCode.Ldnull: stack.Push(null); break;
                case CilCode.Ldc_I4_M1: stack.Push(-1); break;
                case CilCode.Ldc_I4_0: stack.Push(0); break;
                case CilCode.Ldc_I4_1: stack.Push(1); break;
                case CilCode.Ldc_I4_2: stack.Push(2); break;
                case CilCode.Ldc_I4_3: stack.Push(3); break;
                case CilCode.Ldc_I4_4: stack.Push(4); break;
                case CilCode.Ldc_I4_5: stack.Push(5); break;
                case CilCode.Ldc_I4_6: stack.Push(6); break;
                case CilCode.Ldc_I4_7: stack.Push(7); break;
                case CilCode.Ldc_I4_8: stack.Push(8); break;
                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_S: stack.Push(Convert.ToInt32(instr.Operand)); break;
                case CilCode.Ldc_I8: stack.Push(Convert.ToInt64(instr.Operand)); break;
                case CilCode.Ldc_R4: stack.Push(Convert.ToSingle(instr.Operand)); break;
                case CilCode.Ldc_R8: stack.Push(Convert.ToDouble(instr.Operand)); break;
                case CilCode.Ldstr: stack.Push((string?)instr.Operand); break;

                case CilCode.Dup: stack.Push(stack.Count > 0 ? stack.Peek() : null); break;
                case CilCode.Pop: Pop(stack); break;

                case CilCode.Ldloc_0: stack.Push(locals.GetValueOrDefault(0)); break;
                case CilCode.Ldloc_1: stack.Push(locals.GetValueOrDefault(1)); break;
                case CilCode.Ldloc_2: stack.Push(locals.GetValueOrDefault(2)); break;
                case CilCode.Ldloc_3: stack.Push(locals.GetValueOrDefault(3)); break;
                case CilCode.Ldloc:
                case CilCode.Ldloc_S: stack.Push(locals.GetValueOrDefault(LocalIndex(instr))); break;
                case CilCode.Stloc_0: locals[0] = Pop(stack); break;
                case CilCode.Stloc_1: locals[1] = Pop(stack); break;
                case CilCode.Stloc_2: locals[2] = Pop(stack); break;
                case CilCode.Stloc_3: locals[3] = Pop(stack); break;
                case CilCode.Stloc:
                case CilCode.Stloc_S: locals[LocalIndex(instr)] = Pop(stack); break;

                case CilCode.Newarr:
                {
                    int len = ToInt(Pop(stack));
                    stack.Push(new object?[Math.Max(0, len)]);
                    break;
                }
                case CilCode.Ldlen:
                    stack.Push(Pop(stack) is object?[] a ? a.Length : 0);
                    break;
                case CilCode.Stfld:
                {
                    var value = Pop(stack);
                    Pop(stack); // the target object (ThisRef)
                    if (instr.Operand is IFieldDescriptor field)
                        fields[field.Name!] = value;
                    break;
                }
                case CilCode.Ldfld:
                {
                    Pop(stack); // the target object
                    stack.Push(instr.Operand is IFieldDescriptor f && fields.TryGetValue(f.Name!, out var v) ? v : null);
                    break;
                }
                case CilCode.Stelem:
                case CilCode.Stelem_I:
                case CilCode.Stelem_I1:
                case CilCode.Stelem_I2:
                case CilCode.Stelem_I4:
                case CilCode.Stelem_I8:
                case CilCode.Stelem_R4:
                case CilCode.Stelem_R8:
                case CilCode.Stelem_Ref:
                {
                    var value = Pop(stack);
                    int index = ToInt(Pop(stack));
                    if (Pop(stack) is object?[] arr && index >= 0 && index < arr.Length)
                        arr[index] = value;
                    break;
                }
                case CilCode.Ldelem:
                case CilCode.Ldelem_I:
                case CilCode.Ldelem_I1:
                case CilCode.Ldelem_U1:
                case CilCode.Ldelem_I2:
                case CilCode.Ldelem_U2:
                case CilCode.Ldelem_I4:
                case CilCode.Ldelem_U4:
                case CilCode.Ldelem_I8:
                case CilCode.Ldelem_R4:
                case CilCode.Ldelem_R8:
                case CilCode.Ldelem_Ref:
                {
                    int index = ToInt(Pop(stack));
                    stack.Push(Pop(stack) is object?[] arr && index >= 0 && index < arr.Length ? arr[index] : null);
                    break;
                }

                case CilCode.Add: { int b = ToInt(Pop(stack)); stack.Push(ToInt(Pop(stack)) + b); break; }
                case CilCode.Sub: { int b = ToInt(Pop(stack)); stack.Push(ToInt(Pop(stack)) - b); break; }
                case CilCode.Mul: { int b = ToInt(Pop(stack)); stack.Push(ToInt(Pop(stack)) * b); break; }

                case CilCode.Br:
                case CilCode.Br_S:
                    next = LabelIndex(instr, offsetToIndex);
                    break;
                case CilCode.Brtrue:
                case CilCode.Brtrue_S:
                    if (ToBool(Pop(stack))) next = LabelIndex(instr, offsetToIndex);
                    break;
                case CilCode.Brfalse:
                case CilCode.Brfalse_S:
                    if (!ToBool(Pop(stack))) next = LabelIndex(instr, offsetToIndex);
                    break;
                case CilCode.Beq:
                case CilCode.Beq_S:
                    { var rv = Pop(stack); var lv = Pop(stack); if (NumEq(lv, rv)) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Bne_Un:
                case CilCode.Bne_Un_S:
                    { var rv = Pop(stack); var lv = Pop(stack); if (!NumEq(lv, rv)) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Blt:
                case CilCode.Blt_S:
                case CilCode.Blt_Un:
                case CilCode.Blt_Un_S:
                    { int b = ToInt(Pop(stack)); if (ToInt(Pop(stack)) < b) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Bgt:
                case CilCode.Bgt_S:
                case CilCode.Bgt_Un:
                case CilCode.Bgt_Un_S:
                    { int b = ToInt(Pop(stack)); if (ToInt(Pop(stack)) > b) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Ble:
                case CilCode.Ble_S:
                case CilCode.Ble_Un:
                case CilCode.Ble_Un_S:
                    { int b = ToInt(Pop(stack)); if (ToInt(Pop(stack)) <= b) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Bge:
                case CilCode.Bge_S:
                case CilCode.Bge_Un:
                case CilCode.Bge_Un_S:
                    { int b = ToInt(Pop(stack)); if (ToInt(Pop(stack)) >= b) next = LabelIndex(instr, offsetToIndex); break; }
                case CilCode.Switch:
                {
                    int value = ToInt(Pop(stack));
                    if (instr.Operand is IList<ICilLabel> labels && value >= 0 && value < labels.Count
                        && offsetToIndex.TryGetValue((int)labels[value].Offset, out var t))
                        next = t;
                    break;
                }

                case CilCode.Ceq: { var rv = Pop(stack); var lv = Pop(stack); stack.Push(NumEq(lv, rv) ? 1 : 0); break; }
                case CilCode.Clt:
                case CilCode.Clt_Un: { int b = ToInt(Pop(stack)); stack.Push(ToInt(Pop(stack)) < b ? 1 : 0); break; }
                case CilCode.Cgt:
                case CilCode.Cgt_Un: { int b = ToInt(Pop(stack)); stack.Push(ToInt(Pop(stack)) > b ? 1 : 0); break; }

                case CilCode.Call:
                case CilCode.Callvirt:
                    DoCall(module, reader, stack, instr.Operand as IMethodDescriptor);
                    break;

                case CilCode.Ret:
                    return fields;

                default:
                    throw new NotSupportedException(
                        $"read-method interpreter: unsupported opcode {instr.OpCode.Code} in {handler.ReadMethod!.Name}");
            }

            ip = next;
        }

        return fields;
    }

    private static void DoCall(ModuleDefinition module, BinaryReader reader, Stack<object?> stack,
                               IMethodDescriptor? method)
    {
        if (method is null) return;

        if ((method.DeclaringType?.Name?.ToString() ?? "") == "BinaryReader"
            && (method.DeclaringType?.Namespace?.ToString() ?? "") == "System.IO")
        {
            switch (method.Name?.ToString())
            {
                case "ReadBoolean": Pop(stack); stack.Push(reader.ReadBoolean()); return;
                case "ReadByte": Pop(stack); stack.Push((int)reader.ReadByte()); return;
                case "ReadSByte": Pop(stack); stack.Push((int)reader.ReadSByte()); return;
                case "ReadInt16": Pop(stack); stack.Push((int)reader.ReadInt16()); return;
                case "ReadUInt16": Pop(stack); stack.Push((int)reader.ReadUInt16()); return;
                case "ReadInt32": Pop(stack); stack.Push(reader.ReadInt32()); return;
                case "ReadUInt32": Pop(stack); stack.Push(reader.ReadUInt32()); return;
                case "ReadInt64": Pop(stack); stack.Push(reader.ReadInt64()); return;
                case "ReadUInt64": Pop(stack); stack.Push(reader.ReadUInt64()); return;
                case "ReadSingle": Pop(stack); stack.Push(reader.ReadSingle()); return;
                case "ReadDouble": Pop(stack); stack.Push(reader.ReadDouble()); return;
                case "ReadChar": Pop(stack); stack.Push(reader.ReadChar()); return;
                case "ReadString": Pop(stack); stack.Push(ReadStringOperand(module, reader)); return;
                case "ReadBytes": { int n = ToInt(Pop(stack)); Pop(stack); stack.Push(reader.ReadBytes(n)); return; }
            }
        }

        // Any other call: balance the stack per its signature so decoding stays in sync.
        if (method.Signature is MethodSignature sig)
        {
            int pops = sig.ParameterTypes.Count + (sig.HasThis ? 1 : 0);
            for (int i = 0; i < pops; i++) Pop(stack);
            if (!(sig.ReturnType?.IsTypeOf("System", "Void") ?? false))
                stack.Push(null);
        }
    }

    private static DecodedStringLiteral ReadStringOperand(ModuleDefinition module, BinaryReader reader)
    {
        string value = reader.ReadString();
        var index = UserStringsByModule.GetValue(module, BuildUserStringIndex);
        return new DecodedStringLiteral(value, index.RawTokenFor(value));
    }

    private static UserStringIndex BuildUserStringIndex(ModuleDefinition module)
    {
        var offsets = new Dictionary<string, uint>(StringComparer.Ordinal);
        uint nextOffset = 1;
        if (module is SerializedModuleDefinition serialized
            && serialized.DotNetDirectory?.Metadata?.TryGetStream<UserStringsStream>(out var stream) == true)
        {
            nextOffset = checked((uint) stream.GetPhysicalSize());
            // The preserving metadata buffer indexes every imported entry in order, so a duplicate
            // value is represented by its last heap occurrence. Mirror that selection exactly.
            foreach (var (entryOffset, entryValue) in stream.EnumerateStrings())
                offsets[entryValue] = entryOffset;
        }
        return new UserStringIndex(offsets, nextOffset);
    }

    private static object? Pop(Stack<object?> s) => s.Count > 0 ? s.Pop() : null;
    private static int ToInt(object? v) => v is null ? 0 : Convert.ToInt32(v);
    private static bool ToBool(object? v) => v switch { null => false, bool b => b, _ => Convert.ToInt64(v) != 0 };
    private static bool NumEq(object? a, object? b)
        => Equals(a, b) || (a is IConvertible && b is IConvertible && Convert.ToInt64(a) == Convert.ToInt64(b));

    private static int ArgIndex(CilInstruction i) => i.Operand is Parameter p ? p.Index : Convert.ToInt32(i.Operand ?? 0);
    private static int LocalIndex(CilInstruction i) => i.Operand is CilLocalVariable l ? l.Index : Convert.ToInt32(i.Operand ?? 0);

    private static int LabelIndex(CilInstruction i, Dictionary<int, int> map)
        => i.Operand is ICilLabel lbl && map.TryGetValue((int)lbl.Offset, out var idx) ? idx : int.MaxValue;
}
