using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Emit;

/// <summary>Creates a detached body whose labels, locals and EH clauses never alias the source.</summary>
internal static class CilMethodBodyCloner
{
    public static CilMethodBody Clone(CilMethodBody source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var result = new CilMethodBody
        {
            InitializeLocals = source.InitializeLocals,
            MaxStack = source.MaxStack,
        };
        var locals = source.LocalVariables.ToDictionary(local => local,
            local => new CilLocalVariable(local.VariableType),
            ReferenceIdentityComparer<CilLocalVariable>.Instance);
        foreach (var local in source.LocalVariables)
            result.LocalVariables.Add(locals[local]);

        var instructions = source.Instructions.ToDictionary(instruction => instruction,
            instruction => new CilInstruction(instruction.OpCode),
            ReferenceIdentityComparer<CilInstruction>.Instance);
        foreach (var instruction in source.Instructions)
            result.Instructions.Add(instructions[instruction]);
        foreach (var instruction in source.Instructions)
            instructions[instruction].Operand = CloneOperand(instruction.Operand,
                locals, instructions);

        foreach (var handler in source.ExceptionHandlers)
        {
            result.ExceptionHandlers.Add(new CilExceptionHandler
            {
                HandlerType = handler.HandlerType,
                TryStart = CloneLabel(handler.TryStart, instructions),
                TryEnd = CloneLabel(handler.TryEnd, instructions),
                HandlerStart = CloneLabel(handler.HandlerStart, instructions),
                HandlerEnd = CloneLabel(handler.HandlerEnd, instructions),
                FilterStart = CloneLabel(handler.FilterStart, instructions),
                ExceptionType = handler.ExceptionType,
            });
        }
        return result;
    }

    private static object? CloneOperand(object? operand,
        IReadOnlyDictionary<CilLocalVariable, CilLocalVariable> locals,
        IReadOnlyDictionary<CilInstruction, CilInstruction> instructions) => operand switch
    {
        CilLocalVariable local => locals[local],
        ICilLabel label => CloneLabel(label, instructions),
        IList<ICilLabel> labels => labels.Select(label =>
            CloneLabel(label, instructions) ?? new CilInstructionLabel()).ToList(),
        _ => operand,
    };

    private static ICilLabel? CloneLabel(ICilLabel? label,
        IReadOnlyDictionary<CilInstruction, CilInstruction> instructions)
    {
        if (label is null)
            return null;
        if (label is CilInstructionLabel { Instruction: { } instruction }
            && instructions.TryGetValue(instruction, out var mapped))
            return new CilInstructionLabel(mapped);
        return new CilOffsetLabel(label.Offset);
    }
}
