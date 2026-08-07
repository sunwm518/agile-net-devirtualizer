using AgileDevirtualizer.Resource;
using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;

namespace AgileDevirtualizer.Decode;

/// <summary>
/// Turns one <see cref="VMMethod"/>'s raw blobs into a fully decoded method: the opcode table is
/// read, each instruction's operands are decoded by running its handler's read-method against the
/// operand blob (in order, sharing one reader so the blob stays in sync), then locals and EH.
/// </summary>
internal static class MethodDecoder
{
    public static DecodedMethod Decode(ModuleDefinition module, RuntimeModel runtime, VMMethod method)
    {
        var decoded = new DecodedMethod { Source = method };

        using (var stream = new MemoryStream(method.CodeStream, writable: false))
        using (var reader = new BinaryReader(stream))
        {
            int count = reader.ReadInt32();
            var opcodes = new ushort[count];
            for (int i = 0; i < count; i++)
                opcodes[i] = reader.ReadUInt16();

            for (int i = 0; i < count; i++)
            {
                ushort op = opcodes[i];
                if (op >= runtime.Handlers.Count)
                    throw new InvalidDataException($"instruction {i}: opcode {op} out of range (max {runtime.Handlers.Count - 1})");

                var handler = runtime.Handlers[op];
                long before = stream.Position;
                Dictionary<string, object?> operands;
                try
                {
                    operands = OperandDecoder.Decode(module, handler, reader);
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException(
                        $"instruction {i} (opcode {op}, handler {handler.Type.Name}) failed decoding operands " +
                        $"at blob offset {before}: {ex.Message}", ex);
                }

                decoded.Instructions.Add(new VmInstruction { Index = i, Opcode = op, Operands = operands });
            }

            if (stream.Position != stream.Length)
                throw new InvalidDataException(
                    $"operand blob not fully consumed ({stream.Position}/{stream.Length}) — decoder is out of sync");
        }

        decoded.Locals = LocalsDecoder.Read(module, method.LocalVarStream);
        decoded.ExceptionHandlers = EhDecoder.Read(method.EhStream);
        return decoded;
    }
}
