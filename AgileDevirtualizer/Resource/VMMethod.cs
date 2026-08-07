namespace AgileDevirtualizer.Resource;

/// <summary>
/// One entry of the <c>_CSVM</c> method table: a metadata token identifying the real
/// (now-virtualized) method, plus the three raw blobs the runtime consumes.
/// </summary>
internal sealed class VMMethod
{
    public Guid Guid;
    public uint Token;
    public byte[] LocalVarStream = [];
    public byte[] CodeStream = [];
    public byte[] EhStream = [];
}
