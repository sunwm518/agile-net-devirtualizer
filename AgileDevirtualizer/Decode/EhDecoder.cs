namespace AgileDevirtualizer.Decode;

/// <summary>
/// Decodes the exception-handler blob: <c>int32 count</c>, then per clause
/// <c>type, tryStart, tryEnd, handlerStart, handlerEnd</c> (all VM-instruction indices, inclusive
/// bounds as the runtime compares <c>idx &gt;= start &amp;&amp; idx &lt;= end</c>), plus a trailing
/// token for catch (type) and filter clauses. An empty blob means no handlers.
/// </summary>
internal static class EhDecoder
{
    public static List<EhClause> Read(byte[] ehStream)
    {
        var result = new List<EhClause>();
        if (ehStream.Length == 0)
            return result;

        using var stream = new MemoryStream(ehStream, writable: false);
        using var reader = new BinaryReader(stream);
        int count = reader.ReadInt32();
        for (int i = 0; i < count; i++)
        {
            var c = new EhClause
            {
                ClauseType = reader.ReadInt32(),
                TryStart = reader.ReadInt32(),
                TryEnd = reader.ReadInt32(),
                HandlerStart = reader.ReadInt32(),
                HandlerEnd = reader.ReadInt32(),
            };
            c.HasExtraToken = c.ClauseType == 0 || c.ClauseType == 1; // catch (type) or filter
            if (c.HasExtraToken)
                c.ExtraToken = reader.ReadInt32();
            result.Add(c);
        }

        // A correct decode consumes the length-prefixed blob exactly; a mismatch means the EH
        // layout differs from what both observed runtimes use — fail loudly rather than mis-decode.
        if (stream.Position != stream.Length)
            throw new InvalidDataException(
                $"EH blob not fully consumed ({stream.Position}/{stream.Length}) — format drift?");
        return result;
    }
}
