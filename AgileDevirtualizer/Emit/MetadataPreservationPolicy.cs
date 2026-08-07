using AsmResolver.DotNet.Builder;

namespace AgileDevirtualizer.Emit;

/// <summary>Selects metadata preservation that remains safe for each protected module layout.</summary>
internal static class MetadataPreservationPolicy
{
    public static MetadataBuilderFlags ForPartialRewrite(bool preserveAllTokens) =>
        preserveAllTokens
            ? MetadataBuilderFlags.PreserveAll
            // Some protected modules contain a nested TypeDef before its enclosing TypeDef, so
            // preserving definition-table order would corrupt ownership ranges. User-string heap
            // offsets are independent of that order and must still remain stable: VM bytecode keeps
            // raw 0x70xxxxxx tokens for every method that stays virtualized.
            : MetadataBuilderFlags.PreserveUserStringIndices;
}
