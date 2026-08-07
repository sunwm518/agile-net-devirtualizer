using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;

namespace AgileDevirtualizer.Lift;

internal sealed partial class ExecuteInterpreter
{
    /// <summary>
    /// Resolves a metadata type without guessing its class/value-type bit. AsmResolver can report
    /// an already-loaded framework assembly as a duplicate while resolving a later TypeRef. In
    /// that case, search only the context assembly with the same exact identity and then require
    /// the exact metadata full name. If either proof is unavailable, resolution stays unknown.
    /// </summary>
    private TypeDefinition? ResolveTypeDef(ITypeDescriptor? type)
    {
        if (type is null)
            return null;

        try
        {
            if (type.Resolve(_ctx) is { } resolved)
                return resolved;
        }
        catch
        {
            // Fall through to the already-loaded-assembly recovery below.
        }

        var underlying = UnderlyingReference(type);
        var definingAssembly = underlying is null ? null : DefiningAssembly(underlying);
        if (_ctx is null || underlying is not { } reference
            || definingAssembly is not { } wantedAssembly)
            return null;

        foreach (var loadedAssembly in _ctx.GetLoadedAssemblies())
        {
            if (!SameAssemblyIdentity(wantedAssembly, loadedAssembly))
                continue;

            var matches = loadedAssembly.Modules
                .SelectMany(module => module.GetAllTypes())
                .Where(candidate => string.Equals(candidate.FullName, reference.FullName,
                    StringComparison.Ordinal))
                .Take(2)
                .ToArray();
            if (matches.Length == 1)
                return matches[0];
        }

        return null;
    }

    private static ITypeDefOrRef? UnderlyingReference(ITypeDescriptor type) => type switch
    {
        ITypeDefOrRef reference => reference is TypeSpecification specification
            ? specification.Signature?.GetUnderlyingTypeDefOrRef()
            : reference,
        TypeSignature signature => signature.GetUnderlyingTypeDefOrRef(),
        _ => null,
    };

    private static AssemblyDescriptor? DefiningAssembly(ITypeDefOrRef reference) => reference switch
    {
        TypeDefinition definition => definition.DeclaringModule?.Assembly,
        TypeReference typeReference => typeReference.Scope?.GetAssembly(),
        _ => reference.ContextModule?.Assembly,
    };

    private static bool SameAssemblyIdentity(AssemblyDescriptor wanted, AssemblyDescriptor loaded)
    {
        if (!string.Equals(wanted.Name?.ToString(), loaded.Name?.ToString(),
                StringComparison.OrdinalIgnoreCase)
            || wanted.Version != loaded.Version
            || !string.Equals(wanted.Culture?.ToString() ?? string.Empty,
                loaded.Culture?.ToString() ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            return false;

        byte[] wantedToken = PublicKeyToken(wanted);
        byte[] loadedToken = PublicKeyToken(loaded);
        return wantedToken.Length == 0 || loadedToken.Length == 0
            || wantedToken.SequenceEqual(loadedToken);
    }

    private static byte[] PublicKeyToken(AssemblyDescriptor assembly)
    {
        try { return assembly.GetPublicKeyToken() ?? []; }
        catch { return []; }
    }

    private bool IsKnownAssignableTo(TypeSignature actual, ITypeDefOrRef target)
    {
        if (ResolveTypeDef(target) is { } targetDefinition)
        {
            try
            {
                var expected = target.ToTypeSignature(targetDefinition.IsValueType);
                if (actual.IsAssignableTo(expected, _ctx))
                    return true;
            }
            catch
            {
                // The exact metadata walk below remains available after resolver failures.
            }

            if (ResolveTypeDef(actual) is { } actualDefinition)
                return DefinitionDerivesFrom(actualDefinition, targetDefinition);
        }

        return string.Equals(actual.FullName, target.FullName, StringComparison.Ordinal);
    }

    private bool DefinitionDerivesFrom(TypeDefinition actual, TypeDefinition target)
    {
        var pending = new Queue<TypeDefinition>();
        var visited = new HashSet<TypeDefinition>();
        pending.Enqueue(actual);

        while (pending.Count > 0)
        {
            var current = pending.Dequeue();
            if (!visited.Add(current))
                continue;
            if (SameTypeDefinition(current, target))
                return true;

            if (ResolveTypeDef(current.BaseType) is { } baseType)
                pending.Enqueue(baseType);
            foreach (var implementation in current.Interfaces)
                if (ResolveTypeDef(implementation.Interface) is { } interfaceType)
                    pending.Enqueue(interfaceType);
        }

        return false;
    }

    private static bool SameTypeDefinition(TypeDefinition left, TypeDefinition right)
    {
        if (ReferenceEquals(left, right))
            return true;
        return string.Equals(left.FullName, right.FullName, StringComparison.Ordinal)
            && left.DeclaringModule?.Assembly is { } leftAssembly
            && right.DeclaringModule?.Assembly is { } rightAssembly
            && SameAssemblyIdentity(leftAssembly, rightAssembly);
    }
}
