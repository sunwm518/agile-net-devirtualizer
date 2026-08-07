using System.Globalization;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Collections;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Analysis;

internal sealed record ShadowCfgComparisonResult(
    bool Equivalent,
    IReadOnlyList<string> Differences);

/// <summary>
/// Compares two CIL bodies by meaningfully stable structure rather than object identity. Imported
/// metadata references, locals and labels are normalized to signatures and instruction indices.
/// </summary>
internal static class ShadowCfgBodyComparer
{
    public static ShadowCfgComparisonResult Compare(CilMethodBody legacy, CilMethodBody shadow)
    {
        var differences = new List<string>();
        Difference("initialize-locals", legacy.InitializeLocals, shadow.InitializeLocals);
        Difference("max-stack", legacy.MaxStack, shadow.MaxStack);
        Difference("local-count", legacy.LocalVariables.Count, shadow.LocalVariables.Count);
        Difference("instruction-count", legacy.Instructions.Count, shadow.Instructions.Count);
        Difference("handler-count", legacy.ExceptionHandlers.Count, shadow.ExceptionHandlers.Count);

        for (int index = 0; index < Math.Min(
                 legacy.LocalVariables.Count, shadow.LocalVariables.Count); index++)
        {
            Difference($"local[{index}]", legacy.LocalVariables[index].VariableType.FullName,
                shadow.LocalVariables[index].VariableType.FullName);
        }

        for (int index = 0; index < Math.Min(
                 legacy.Instructions.Count, shadow.Instructions.Count); index++)
        {
            var expected = legacy.Instructions[index];
            var actual = shadow.Instructions[index];
            Difference($"instruction[{index}].opcode", expected.OpCode.Code, actual.OpCode.Code);
            Difference($"instruction[{index}].operand",
                NormalizeOperand(legacy, expected.Operand),
                NormalizeOperand(shadow, actual.Operand));
        }

        for (int index = 0; index < Math.Min(
                 legacy.ExceptionHandlers.Count, shadow.ExceptionHandlers.Count); index++)
        {
            var expected = legacy.ExceptionHandlers[index];
            var actual = shadow.ExceptionHandlers[index];
            Difference($"handler[{index}].kind", expected.HandlerType, actual.HandlerType);
            Difference($"handler[{index}].try-start", LabelIndex(legacy, expected.TryStart),
                LabelIndex(shadow, actual.TryStart));
            Difference($"handler[{index}].try-end", LabelIndex(legacy, expected.TryEnd),
                LabelIndex(shadow, actual.TryEnd));
            Difference($"handler[{index}].handler-start",
                LabelIndex(legacy, expected.HandlerStart),
                LabelIndex(shadow, actual.HandlerStart));
            Difference($"handler[{index}].handler-end", LabelIndex(legacy, expected.HandlerEnd),
                LabelIndex(shadow, actual.HandlerEnd));
            Difference($"handler[{index}].filter-start",
                LabelIndex(legacy, expected.FilterStart),
                LabelIndex(shadow, actual.FilterStart));
            Difference($"handler[{index}].exception-type", expected.ExceptionType?.FullName,
                actual.ExceptionType?.FullName);
        }

        return new ShadowCfgComparisonResult(differences.Count == 0, differences);

        void Difference(string location, object? expected, object? actual)
        {
            if (!Equals(expected, actual))
                differences.Add($"{location}: legacy={expected ?? "<null>"}; shadow={actual ?? "<null>"}");
        }
    }

    private static string NormalizeOperand(CilMethodBody body, object? operand) => operand switch
    {
        null => "<none>",
        CilLocalVariable local => $"local:{LocalIndex(body, local)}:{local.VariableType.FullName}",
        Parameter parameter => $"arg:{parameter.Index}:{parameter.ParameterType.FullName}",
        ICilLabel label => $"label:{LabelIndex(body, label)}",
        IEnumerable<ICilLabel> labels => "labels:[" +
            string.Join(',', labels.Select(label => LabelIndex(body, label))) + "]",
        MemberReference member => $"member:{member.FullName}",
        IMethodDescriptor method => $"method:{method.FullName}",
        IFieldDescriptor field => $"field:{field.FullName}",
        ITypeDescriptor type => $"type:{type.FullName}",
        IFormattable formattable => $"value:{formattable.ToString(null, CultureInfo.InvariantCulture)}",
        _ => $"value:{operand}",
    };

    private static int LocalIndex(CilMethodBody body, CilLocalVariable local)
    {
        for (int index = 0; index < body.LocalVariables.Count; index++)
            if (ReferenceEquals(body.LocalVariables[index], local))
                return index;
        return -1;
    }

    private static int? LabelIndex(CilMethodBody body, ICilLabel? label)
    {
        if (label is null)
            return null;
        for (int index = 0; index < body.Instructions.Count; index++)
            if (body.Instructions[index].Offset == label.Offset)
                return index;
        if (body.Instructions.Count > 0)
        {
            var final = body.Instructions[^1];
            if (label.Offset == final.Offset + final.Size)
                return body.Instructions.Count;
        }
        return -1;
    }
}
