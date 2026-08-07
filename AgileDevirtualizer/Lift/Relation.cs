namespace AgileDevirtualizer.Lift;

/// <summary>
/// The comparison a VM condition helper computes, recovered by probing (not by name). Maps directly
/// onto CIL: Falsy↔brfalse/ceq-with-0, Eq↔beq/ceq, Lt↔blt/clt, Gt↔bgt/cgt, and so on.
/// </summary>
internal enum Relation
{
    Falsy, // one operand, true when zero/null  (brtrue/brfalse family)
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}
