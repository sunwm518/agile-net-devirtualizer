namespace AgileDevirtualizer.Lift;

/// <summary>
/// Raised when the lifter meets a construct it does not yet model. We fail the whole VM instruction
/// loudly rather than emit a guess — a wrong instruction is far worse than a reported gap.
/// </summary>
internal sealed class LiftUnsupported(string message) : Exception(message);
