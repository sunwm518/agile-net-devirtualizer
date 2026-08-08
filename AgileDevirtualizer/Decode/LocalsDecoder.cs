using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Decode;

/// <summary>
/// Decodes the local-variable blob. Each local is a 4-byte <c>CorElementType</c> discriminator;
/// VALUETYPE/VAR/MVAR add a 4-byte type token, GENERICINST adds a 4-byte flag (+token when the
/// flag is VALUETYPE). Mirrors the runtime's per-local reader; primitives carry no extra bytes.
/// </summary>
internal static class LocalsDecoder
{
    public static List<TypeSignature> Read(ModuleDefinition module, byte[] localVarStream)
    {
        var result = new List<TypeSignature>();
        if (localVarStream.Length == 0)
            return result;

        using var stream = new MemoryStream(localVarStream, writable: false);
        using var reader = new BinaryReader(stream);
        int count = reader.ReadInt32();
        for (int i = 0; i < count; i++)
            result.Add(ReadOne(module, reader));

        // Fail loudly if our understanding of the format ever drifts: a correct decode consumes the
        // length-prefixed blob exactly. A tail (or an EOF above) means the layout changed.
        if (stream.Position != stream.Length)
            throw new InvalidDataException(
                $"locals blob not fully consumed ({stream.Position}/{stream.Length}) — format drift?");
        return result;
    }

    private static TypeSignature ReadOne(ModuleDefinition module, BinaryReader reader)
    {
        var f = module.CorLibTypeFactory;
        int code = reader.ReadInt32();
        switch (code)
        {
            case 0x02: return f.Boolean;
            case 0x03: return f.Char;
            case 0x04: return f.SByte;
            case 0x05: return f.Byte;
            case 0x06: return f.Int16;
            case 0x07: return f.UInt16;
            case 0x08: return f.Int32;
            case 0x09: return f.UInt32;
            case 0x0A: return f.Int64;
            case 0x0B: return f.UInt64;
            case 0x0C: return f.Single;
            case 0x0D: return f.Double;
            case 0x0E: return f.String;
            // Only VALUETYPE/VAR/MVAR carry a trailing type token (matches the runtime's per-local
            // reader). CLASS/STRING/PTR/ARRAY/SZARRAY/OBJECT/etc. carry no payload — the runtime
            // just seeds a null/default value — so they must NOT consume extra bytes.
            case 0x11: // VALUETYPE
            case 0x13: // VAR
            case 0x1E: // MVAR
                return ResolveToken(module, reader.ReadUInt32());
            case 0x15: // GENERICINST
                int flag = reader.ReadInt32();
                return flag == 0x11 ? ResolveToken(module, reader.ReadUInt32()) : f.Object;
            case 0x18: return f.IntPtr;
            case 0x19: return f.UIntPtr;
            default:
                return f.Object;
        }
    }

    private static TypeSignature ResolveToken(ModuleDefinition module, uint token)
    {
        if (module.TryLookupMember(new MetadataToken(token), out var m))
        {
            if (m is TypeSpecification spec && spec.Signature is { } s)
                return s;
            if (m is ITypeDefOrRef t)
                return t.ToTypeSignature(SafeResolve.Type(t)?.IsValueType ?? false);
        }
        return module.CorLibTypeFactory.Object;
    }
}
