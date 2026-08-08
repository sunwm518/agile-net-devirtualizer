using AsmResolver.DotNet;

namespace AgileDevirtualizer.Runtime;

/// <summary>
/// AsmResolver's <c>Resolve(null)</c> throws for a handful of reference shapes that need a real
/// runtime context (e.g. some cross-assembly references) rather than returning null the way an
/// ordinary unresolved same-assembly reference does. Every caller here is a heuristic probe over an
/// input module that might not even be a real Agile.NET runtime or protected assembly, so a resolve
/// failure must mean "not a match" — never an unhandled crash that dumps a local file-path stack
/// trace for an arbitrary DLL a user pointed the tool at.
/// </summary>
internal static class SafeResolve
{
    public static TypeDefinition? Type(ITypeDescriptor? type)
    {
        if (type is null) return null;
        try { return type.Resolve(null); }
        catch { return null; }
    }

    public static MethodDefinition? Method(IMethodDefOrRef? method)
    {
        if (method is null) return null;
        try { return method.Resolve(null); }
        catch { return null; }
    }
}
