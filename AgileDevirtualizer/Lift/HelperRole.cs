namespace AgileDevirtualizer.Lift;

/// <summary>
/// The effect a runtime helper method (or an inline BCL call) has, recognized by the BCL API it is
/// anchored on — never by name. The execute-method lifter uses these to turn VM plumbing back into
/// concrete CIL (calls, newobj, field access, token resolution).
/// </summary>
internal enum HelperRole
{
    None,
    ResolveMethod,  // System.Reflection.Module.ResolveMethod(int)  -> a method token
    ResolveField,   // System.Reflection.Module.ResolveField(int)   -> a field token
    ResolveType,    // System.Reflection.Module.ResolveType(int)    -> a type token
    ResolveString,  // System.Reflection.Module.ResolveString(int)  -> a string token
    ResolveMember,  // System.Reflection.Module.ResolveMember(int)  -> a field OR method token (ambiguous
                    // until DoResolve classifies the resolved member's own signature)
    Invoke,         // MethodBase.Invoke(...)        -> call / callvirt
    NewObj,         // ConstructorInfo.Invoke(...)   -> newobj
    FieldSet,       // FieldInfo.SetValue(...)       -> stfld / stsfld
    FieldGet,       // FieldInfo.GetValue(...)       -> ldfld / ldsfld
    CoerceByRef,    // runtime void(ref object, Type), anchored on Enum.ToObject
}
