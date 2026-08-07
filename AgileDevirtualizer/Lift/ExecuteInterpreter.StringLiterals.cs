using AsmResolver.PE.DotNet.Cil;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Native ldstr has only a 24-bit user-string offset. Agile's resolver also accepts 0x71...
    /// raw values, so those strings are reconstructed exactly through char[] instead.
    /// </summary>
    private void EmitResolvedString(SymValue.ResolvedString resolved)
    {
        if ((resolved.RawToken & 0xFF000000u) == 0x70000000u)
        {
            Emit(CilOpCodes.Ldstr, resolved.Value);
            return;
        }

        Emit(CilOpCodes.Ldc_I4, resolved.Value.Length);
        Emit(CilOpCodes.Newarr, _module.CorLibTypeFactory.Char.ToTypeDefOrRef());
        for (int i = 0; i < resolved.Value.Length; i++)
        {
            Emit(CilOpCodes.Dup);
            Emit(CilOpCodes.Ldc_I4, i);
            Emit(CilOpCodes.Ldc_I4, (int) resolved.Value[i]);
            Emit(CilOpCodes.Stelem_I2);
        }
        Emit(CilOpCodes.Newobj, StringFromCharsCtorMarker.Instance);
    }
}
