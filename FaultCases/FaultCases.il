.assembly extern mscorlib
{
  .ver 4:0:0:0
}
.assembly FaultCases
{
  .ver 1:0:0:0
}
.module FaultCases.dll

.namespace FaultCases
{
  .class public abstract sealed auto ansi beforefieldinit FaultPatterns
         extends [mscorlib]System.Object
  {
    .field public static int32 LastFaultState

    .method public hidebysig static int32 FaultFlow(int32 mode) cil managed
    {
      .maxstack 2
      .locals init ([0] int32 result)

      ldc.i4.0
      stsfld int32 FaultCases.FaultPatterns::LastFaultState
      ldc.i4.0
      stloc.0

      .try
      {
        ldarg.0
        brtrue.s THROW_CASE

        ldc.i4.s 10
        stloc.0
        leave.s DONE

      THROW_CASE:
        ldstr "fault-case"
        newobj instance void [mscorlib]System.InvalidOperationException::.ctor(string)
        throw
      }
      fault
      {
        ldc.i4.s 77
        stsfld int32 FaultCases.FaultPatterns::LastFaultState
        endfinally
      }

    DONE:
      ldloc.0
      ret
    }
  }
}
