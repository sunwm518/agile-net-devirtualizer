using System.Runtime.CompilerServices;

namespace AgileDevirtualizer.Emit;

internal sealed class ReferenceIdentityComparer<T> : IEqualityComparer<T> where T : class
{
    public static ReferenceIdentityComparer<T> Instance { get; } = new();

    public bool Equals(T? left, T? right) => ReferenceEquals(left, right);

    public int GetHashCode(T value) => RuntimeHelpers.GetHashCode(value);
}
