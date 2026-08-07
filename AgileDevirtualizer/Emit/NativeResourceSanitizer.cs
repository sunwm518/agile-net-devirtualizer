using AsmResolver.DotNet;

namespace AgileDevirtualizer.Emit;

/// <summary>
/// Some Agile.NET outputs retain a non-empty native-resource data-directory entry whose payload is
/// truncated. AsmResolver cannot preserve a directory it cannot parse. Clear only that proven-bad
/// directory; valid icons, version resources and manifests are left untouched.
/// </summary>
internal static class NativeResourceSanitizer
{
    public static bool RemoveMalformedDirectory(ModuleDefinition module)
    {
        ArgumentNullException.ThrowIfNull(module);
        try
        {
            _ = module.NativeResourceDirectory;
            return false;
        }
        catch (Exception exception) when (ContainsTruncatedResourceFailure(exception))
        {
            module.NativeResourceDirectory = null;
            return true;
        }
    }

    private static bool ContainsTruncatedResourceFailure(Exception exception)
    {
        if (exception is EndOfStreamException)
            return true;
        if (exception is AggregateException aggregate)
            return aggregate.InnerExceptions.Count > 0
                && aggregate.InnerExceptions.All(ContainsTruncatedResourceFailure);
        return exception.InnerException is not null
            && ContainsTruncatedResourceFailure(exception.InnerException);
    }
}
