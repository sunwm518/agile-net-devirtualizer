using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;

namespace AgileDevirtualizer.Resource;

/// <summary>
/// Locates and parses the <c>_CSVM</c> manifest resource that holds the virtualized method
/// table. Detection is by successful self-validating parse (the table must consume its bytes
/// exactly and every token must resolve to a real method), so it does not rely on the name.
/// </summary>
internal static class VMResource
{
    public static (ManifestResource resource, List<VMMethod> methods)? Find(ModuleDefinition module)
    {
        foreach (var resource in module.Resources)
        {
            if (!resource.IsEmbedded)
                continue;
            var data = resource.GetData();
            if (data is null || data.Length < 4)
                continue;
            if (TryParse(module, data, out var methods))
                return (resource, methods);
        }
        return null;
    }

    public static bool TryParse(ModuleDefinition module, byte[] data, out List<VMMethod> methods)
    {
        methods = [];
        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(stream);

            int count = reader.ReadInt32();
            if (count <= 0 || count > 500_000)
                return false;

            var result = new List<VMMethod>(count);
            for (int i = 0; i < count; i++)
            {
                var guid = reader.ReadBytes(16);
                if (guid.Length != 16)
                    return false;

                var m = new VMMethod
                {
                    Guid = new Guid(guid),
                    Token = reader.ReadUInt32(),
                };

                // The token must name an actual method in this module.
                if (!module.TryLookupMember(new MetadataToken(m.Token), out var member)
                    || member is not MethodDefinition)
                    return false;

                m.LocalVarStream = ReadBlob(reader);
                m.CodeStream = ReadBlob(reader);
                m.EhStream = ReadBlob(reader);
                result.Add(m);
            }

            // A valid table is consumed exactly — a leftover tail means we mis-parsed.
            if (stream.Position != stream.Length)
                return false;

            methods = result;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] ReadBlob(BinaryReader reader)
    {
        int len = reader.ReadInt32();
        long remaining = reader.BaseStream.Length - reader.BaseStream.Position;
        if (len < 0 || len > remaining)
            throw new InvalidDataException("Bad length prefix in _CSVM table.");
        return reader.ReadBytes(len);
    }
}
