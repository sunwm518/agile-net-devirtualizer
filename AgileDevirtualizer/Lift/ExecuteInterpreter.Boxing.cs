using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Guards the narrow DoInvoke boxing path against stale handler bookkeeping values. The actual
    /// final argument is already present at the tail of emitted CIL, so only box a tracked value type
    /// when that tail can carry the same stack representation. A proven reference-producing tail
    /// (for example <c>castclass Byte[]</c>) must never receive a stale <c>box Int32</c>/<c>box Enum</c>.
    /// </summary>
    private bool TailCanCarryValueType(TypeSignature type)
    {
        if (_out.Count == 0)
            return false;

        var operation = _out[^1];
        return operation.OpCode.Code switch
        {
            CilCode.Ldc_I4 or CilCode.Ldc_I4_S or CilCode.Ldc_I4_M1
                or CilCode.Ldc_I4_0 or CilCode.Ldc_I4_1 or CilCode.Ldc_I4_2 or CilCode.Ldc_I4_3
                or CilCode.Ldc_I4_4 or CilCode.Ldc_I4_5 or CilCode.Ldc_I4_6 or CilCode.Ldc_I4_7
                or CilCode.Ldc_I4_8 => IsI4OrEnumStackType(type),
            CilCode.Ldc_I8 => type.IsTypeOf("System", "Int64") || type.IsTypeOf("System", "UInt64"),
            CilCode.Ldc_R4 => type.IsTypeOf("System", "Single"),
            CilCode.Ldc_R8 => type.IsTypeOf("System", "Double"),
            CilCode.Conv_I or CilCode.Conv_U =>
                type.IsTypeOf("System", "IntPtr") || type.IsTypeOf("System", "UIntPtr"),
            CilCode.Conv_I1 or CilCode.Conv_U1 or CilCode.Conv_I2 or CilCode.Conv_U2
                or CilCode.Conv_I4 or CilCode.Conv_U4 => IsI4OrEnumStackType(type),
            CilCode.Conv_I8 or CilCode.Conv_U8 =>
                type.IsTypeOf("System", "Int64") || type.IsTypeOf("System", "UInt64"),
            CilCode.Unbox_Any when operation.Operand is ITypeDefOrRef unboxed =>
                SameType(type, TypeSignatureOf(unboxed)),
            CilCode.Call or CilCode.Callvirt when operation.Operand is IMethodDescriptor called =>
                SameType(type, SigReturn(called)),
            CilCode.Ldloc when operation.Operand is int local =>
                SameType(type, DeclaredType(_vmLocalTypes, local)),
            CilCode.Ldarg when operation.Operand is int argument =>
                SameType(type, DeclaredType(_vmArgTypes, argument)),
            _ => false,
        };
    }

    private bool IsI4OrEnumStackType(TypeSignature type)
    {
        if (IsI4StackType(type))
            return true;

        try
        {
            var definition = ResolveTypeDef(type);
            return definition is { IsEnum: true }
                && IsI4StackType(definition.GetEnumUnderlyingType());
        }
        catch { return false; }
    }

    private static bool SameType(TypeSignature expected, TypeSignature? actual) =>
        actual is not null && expected.FullName == actual.FullName;
}
