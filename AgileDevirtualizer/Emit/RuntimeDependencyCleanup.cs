using AgileDevirtualizer.Runtime;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Removes VM bytecode only after every protected method was rebuilt, and verifies dependency
/// removal against the assembly that was actually serialized rather than an optimistic in-memory
/// reference scan.
/// </summary>
internal static class RuntimeDependencyCleanup
{
    public static bool RemoveVmResourceWhenComplete(ModuleDefinition module, ManifestResource resource,
                                                     DevirtResult result)
    {
        if (result.Total == 0 || result.Devirtualized != result.Total)
            return false;

        module.Resources.Remove(resource);
        return true;
    }

    public static bool OutputReferencesRuntime(string outputPath, RuntimeModel runtime)
    {
        string? runtimeName = runtime.Module.Assembly?.Name?.ToString();
        if (string.IsNullOrEmpty(runtimeName))
            return true;

        string fullPath = Path.GetFullPath(outputPath);
        var readerParameters = new ModuleReaderParameters(Path.GetDirectoryName(fullPath));
        var output = ModuleDefinition.FromFile(fullPath, readerParameters);
        return output.AssemblyReferences.Any(reference =>
            string.Equals(reference.Name?.ToString(), runtimeName, StringComparison.OrdinalIgnoreCase));
    }
}
