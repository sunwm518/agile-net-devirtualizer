using System.Text;
using AgileDevirtualizer.Decode;
using AgileDevirtualizer.Lift;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Diagnostics;

/// <summary>
/// Builds an observational block/edge view from legacy LiftedOps. It does not participate in
/// lifting or emission; its purpose is to reveal when the linear pipeline needs a real CFG.
/// </summary>
internal static class LegacyCfgDiagnostics
{
    private sealed record Block(int Id, int Start, int End);
    private sealed record Edge(int Source, int Target, string Kind, int SourceIndex, int TargetIndex);

    public static void Write(string directory, DecodedMethod decoded,
                             IReadOnlyList<List<LiftedOp>> lifted, Action<string, string> write)
    {
        int count = decoded.Instructions.Count;
        if (count == 0)
        {
            write("03-blocks.txt", "<no VM instructions>" + Environment.NewLine);
            write("04-cfg.dot", "digraph cfg { }" + Environment.NewLine);
            return;
        }

        var leaders = new SortedSet<int> { 0 };
        foreach (var handler in decoded.ExceptionHandlers)
        {
            AddLeader(leaders, handler.TryStart, count);
            AddLeader(leaders, handler.TryEnd + 1, count);
            AddLeader(leaders, handler.HandlerStart, count);
            AddLeader(leaders, handler.HandlerEnd + 1, count);
        }
        for (int i = 0; i < lifted.Count; i++)
        {
            foreach (var operation in lifted[i])
            {
                if (operation.Operand is VmTarget target)
                    AddLeader(leaders, target.Index, count);
                else if (operation.Operand is VmTarget[] table)
                    foreach (var item in table)
                        AddLeader(leaders, item.Index, count);
                if (IsTerminator(operation.OpCode.Code))
                    AddLeader(leaders, i + 1, count);
            }
        }

        int[] starts = leaders.ToArray();
        var blocks = new List<Block>(starts.Length);
        for (int i = 0; i < starts.Length; i++)
            blocks.Add(new Block(i, starts[i], (i + 1 < starts.Length ? starts[i + 1] : count) - 1));

        int BlockAt(int index)
        {
            for (int i = blocks.Count - 1; i >= 0; i--)
                if (index >= blocks[i].Start)
                    return blocks[i].Id;
            return 0;
        }

        var edges = new List<Edge>();
        foreach (var block in blocks)
        {
            int sourceIndex = block.End;
            LiftedOp? terminator = sourceIndex < lifted.Count ? lifted[sourceIndex].LastOrDefault() : null;
            int fallthrough = sourceIndex + 1;
            if (terminator?.Operand is VmTarget[] table)
            {
                foreach (var target in table)
                    AddEdge(edges, block.Id, target.Index, "SwitchCase", sourceIndex, count, BlockAt);
                AddEdge(edges, block.Id, fallthrough, "SwitchDefault", sourceIndex, count, BlockAt);
            }
            else if (terminator?.Operand is VmTarget target)
            {
                string kind = IsConditional(terminator.OpCode.Code) ? "Conditional" : "Branch";
                AddEdge(edges, block.Id, target.Index, kind, sourceIndex, count, BlockAt);
                if (IsConditional(terminator.OpCode.Code))
                    AddEdge(edges, block.Id, fallthrough, "Fallthrough", sourceIndex, count, BlockAt);
            }
            else if (terminator is null || !IsTerminalWithoutTarget(terminator.OpCode.Code))
            {
                AddEdge(edges, block.Id, fallthrough, "Fallthrough", sourceIndex, count, BlockAt);
            }
        }

        var text = new StringBuilder();
        foreach (var block in blocks)
        {
            text.AppendLine($"B{block.Id}: VM [{block.Start}..{block.End}] "
                + $"regions={RegionsAt(decoded, block.Start)}");
            for (int i = block.Start; i <= block.End; i++)
            {
                text.AppendLine($"  #{i:D4} {decoded.Instructions[i]}");
                if (i < lifted.Count)
                    foreach (var operation in lifted[i])
                        text.AppendLine("    " + operation);
            }
        }
        text.AppendLine("Edges:");
        foreach (var edge in edges)
        {
            string crossing = RegionsAt(decoded, edge.SourceIndex) == RegionsAt(decoded, edge.TargetIndex)
                ? "same-region"
                : "cross-region";
            text.AppendLine($"B{edge.Source} -> B{edge.Target} kind={edge.Kind} {crossing} "
                + $"source={RegionsAt(decoded, edge.SourceIndex)} "
                + $"target={RegionsAt(decoded, edge.TargetIndex)}");
        }
        write("03-blocks.txt", text.ToString());

        var dot = new StringBuilder("digraph cfg {\n  rankdir=TB;\n");
        foreach (var block in blocks)
            dot.AppendLine($"  B{block.Id} [label=\"B{block.Id} [{block.Start}..{block.End}]\\n"
                + $"{Escape(RegionsAt(decoded, block.Start))}\"];");
        foreach (var edge in edges)
            dot.AppendLine($"  B{edge.Source} -> B{edge.Target} [label=\"{edge.Kind}\"];");
        dot.AppendLine("}");
        write("04-cfg.dot", dot.ToString());
    }

    private static void AddEdge(List<Edge> edges, int sourceBlock, int targetIndex, string kind,
                                int sourceIndex, int count, Func<int, int> blockAt)
    {
        if (targetIndex < 0 || targetIndex >= count)
            return;
        edges.Add(new Edge(sourceBlock, blockAt(targetIndex), kind, sourceIndex, targetIndex));
    }

    private static void AddLeader(SortedSet<int> leaders, int index, int count)
    {
        if (index >= 0 && index < count)
            leaders.Add(index);
    }

    private static string RegionsAt(DecodedMethod decoded, int index)
    {
        if (index < 0 || index >= decoded.Instructions.Count)
            return "outside";
        var regions = new List<string>();
        for (int i = 0; i < decoded.ExceptionHandlers.Count; i++)
        {
            var handler = decoded.ExceptionHandlers[i];
            if (index >= handler.TryStart && index <= handler.TryEnd)
                regions.Add($"EH{i}.Try");
            if (index >= handler.HandlerStart && index <= handler.HandlerEnd)
                regions.Add($"EH{i}.Handler");
        }
        return regions.Count == 0 ? "outside" : string.Join(">", regions);
    }

    private static bool IsConditional(CilCode code) => code is
        CilCode.Brtrue or CilCode.Brtrue_S or CilCode.Brfalse or CilCode.Brfalse_S or
        CilCode.Beq or CilCode.Beq_S or CilCode.Bne_Un or CilCode.Bne_Un_S or
        CilCode.Blt or CilCode.Blt_S or CilCode.Blt_Un or CilCode.Blt_Un_S or
        CilCode.Bgt or CilCode.Bgt_S or CilCode.Bgt_Un or CilCode.Bgt_Un_S or
        CilCode.Ble or CilCode.Ble_S or CilCode.Ble_Un or CilCode.Ble_Un_S or
        CilCode.Bge or CilCode.Bge_S or CilCode.Bge_Un or CilCode.Bge_Un_S;

    private static bool IsTerminator(CilCode code) =>
        code is CilCode.Br or CilCode.Br_S or CilCode.Switch || IsConditional(code)
        || IsTerminalWithoutTarget(code);

    private static bool IsTerminalWithoutTarget(CilCode code) => code is
        CilCode.Ret or CilCode.Throw or CilCode.Rethrow or CilCode.Endfinally or CilCode.Endfilter;

    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
