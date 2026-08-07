using System.Security.Cryptography;
using System.Text;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Runtime;

/// <summary>
/// A name-independent description of one generated Agile.NET VM runtime.
/// It is diagnostic only: production decoding never selects behavior from this fingerprint.
/// </summary>
internal sealed record RuntimeStructureFingerprint(
    int HandlerCount,
    int ReadMethodCount,
    int ExecuteMethodCount,
    int ExecuteSwitchCount,
    int LargeExecuteMethodCount,
    int TotalExecuteInstructions,
    int MedianExecuteInstructions,
    int MaximumExecuteInstructions,
    string ExecuteShapeHash)
{
    private const int LargeMethodInstructionFloor = 96;

    public static RuntimeStructureFingerprint Create(RuntimeModel runtime)
    {
        ArgumentNullException.ThrowIfNull(runtime);

        var lengths = new List<int>();
        var opcodeHistogram = new SortedDictionary<int, int>();
        int executeSwitches = 0;
        int largeMethods = 0;

        foreach (var handler in runtime.Handlers)
        {
            if (handler.ExecuteMethod?.CilMethodBody is not { } body)
                continue;

            int length = body.Instructions.Count;
            lengths.Add(length);
            if (length >= LargeMethodInstructionFloor)
                largeMethods++;

            foreach (var instruction in body.Instructions)
            {
                int code = (int)instruction.OpCode.Code;
                opcodeHistogram.TryGetValue(code, out int count);
                opcodeHistogram[code] = count + 1;
                if (instruction.OpCode.Code == CilCode.Switch)
                    executeSwitches++;
            }
        }

        lengths.Sort();
        int total = lengths.Sum();
        int median = lengths.Count == 0 ? 0 : lengths[(lengths.Count - 1) / 2];
        int maximum = lengths.Count == 0 ? 0 : lengths[^1];

        var shape = new StringBuilder();
        shape.Append(runtime.Handlers.Count).Append('|')
            .Append(lengths.Count).Append('|')
            .Append(executeSwitches).Append('|')
            .Append(largeMethods).Append('|');
        foreach (var (code, count) in opcodeHistogram)
            shape.Append(code).Append(':').Append(count).Append(';');

        string hash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(shape.ToString())))[..16];

        return new RuntimeStructureFingerprint(
            runtime.Handlers.Count,
            runtime.Handlers.Count(handler => handler.ReadMethod is not null),
            runtime.Handlers.Count(handler => handler.ExecuteMethod is not null),
            executeSwitches,
            largeMethods,
            total,
            median,
            maximum,
            hash);
    }

    public override string ToString() =>
        $"handlers={HandlerCount} read={ReadMethodCount} exec={ExecuteMethodCount} " +
        $"switches={ExecuteSwitchCount} large={LargeExecuteMethodCount} " +
        $"execute-il={TotalExecuteInstructions} median={MedianExecuteInstructions} " +
        $"max={MaximumExecuteInstructions} shape={ExecuteShapeHash}";
}
