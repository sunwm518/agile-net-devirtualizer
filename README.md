# AgileDevirtualizer

A generic devirtualizer for **Agile.NET** (formerly CodeVeil / SecureTeam) method virtualization,
built from scratch by reverse-engineering the runtime the protector ships alongside every protected
assembly. It reads whatever `AgileDotNet.VMRuntime.dll` a given build shipped with, derives the
opcode map and handler semantics from that DLL at run time, and rewrites each virtualized method body
back into ordinary, verifiable CIL — no hardcoded opcode tables, no per-build patches, no name-based
matching.

## What "generic" means here

Agile.NET's protector randomizes the opcode-to-handler mapping and every identifier on each build, and
duplicates semantically identical handler classes to defeat naive pattern matching. This project never
hardcodes a table of "opcode 7 means `add`" for a specific version. Instead, at load time it:

1. Finds the handler base type structurally (the type with the two abstract methods every handler
   overrides — one that reads operands from a `BinaryReader`, one that executes against the VM
   context) and reads the **registration order** of the opcode dispatch table.
2. For each handler, *interprets* its own read-method IL against the real operand bytes, and
   *classifies* its execute-method IL by abstractly interpreting it over a symbolic model of the VM's
   stack/locals/args — never by name, since names are randomized per build.
3. Lifts the resulting per-instruction semantics into a formal control-flow graph, runs SSA/SCCP/dead-code
   elimination on it, and emits real CIL — locals, exception handlers, branch targets, everything.

The same code has been run, unmodified, against Agile.NET builds `6.6.0.35` and `6.6.0.42`, in both the
"expanded" (500+ one-op handler classes) and "compact" (a dozen group-dispatch handlers) layouts the
protector can emit, and against a fixture whose virtualized method uses `try`/`catch`/`filter`/`fault`/
`rethrow` together. See [`AgileDevirtualizer/DESIGN.md`](AgileDevirtualizer/DESIGN.md) for the full
architecture writeup and the [`VALIDATION.md`](VALIDATION.md) methodology.

## Scope and intent

This is a **method-body devirtualizer**, not a general "unprotect anything" tool. It reverses the one
specific transformation Agile.NET's VM layer applies to a method — VM bytecode back to CIL that a
normal decompiler can read. It does not:

- crack license checks or any application-specific logic — it does not know or care what a method
  *does*, only how to reverse the *encoding* the VM protection applied to it;
- target a specific product — the engine is driven entirely by whatever `AgileDotNet.VMRuntime.dll`
  is on disk, and has no knowledge of any particular protected application;
- undo Agile.NET's separate, unrelated identifier-renaming pass — a devirtualized method still has
  whatever obfuscated names the protector assigned; that is a different transformation this tool does
  not touch;
- ship or require any part of Agile.NET's own binaries — you provide your own protected assembly and
  its accompanying runtime DLL as input; nothing proprietary is bundled here.

Built and published as security-research / interoperability tooling — the same category as `de4dot` or
the various dnSpy unpacking plugins for other .NET protectors.

## How Agile.NET's VM protection works

Agile.NET stores each virtualized method's bytecode in a manifest resource named `_CSVM`. For every
protected method, the resource holds a byte stream of `[instruction count][opcode...][operand blob]`,
plus separately encoded locals and exception-handler tables. The original method body is replaced with
a single call into the runtime's dispatcher — `CSVMRuntime.RunMethod("<guid>", args)` — so a plain
decompiler only ever sees that one opaque call; the real logic lives in the resource, interpreted by
handler classes inside `AgileDotNet.VMRuntime.dll` at run time.

Two runtime generations exist and are handled uniformly: a modern one with 500+ small, heavily
duplicated one-instruction handler classes, and a classic one with under a dozen large "group" handlers
that internally dispatch a family of related instructions via a discriminator byte. Handlers are not
always one VM-opcode-to-one-CIL-instruction either — many encode a whole fused basic block (e.g. "load
argument, call, store field, return" as a single opcode). The lifter is built around that shape.

## The devirtualization pipeline

```
runtime DLL ──► RuntimeModel ─────────────► opcode → handler map
                                             per-handler read/execute methods
protected .exe ──► _CSVM resource ──► per-method: [instructions][operand blob][locals][EH table]
                        │
                        ├─ OperandDecoder:  interprets each handler's own read-method IL against the
                        │                   real operand bytes (so operand layout is derived, not assumed)
                        ├─ HandlerClassifier: abstractly interprets each handler's execute-method IL,
                        │                   recognizing its effect as one CIL instruction/small template
                        ▼
                 formal control-flow graph (typed blocks, exception regions, edge kinds)
                        │
                        ├─ SSA construction, SCCP, dead-code elimination
                        ├─ dispatcher-loop elimination (the VM's own state-machine wrapping, once
                        │   recognized structurally, is removed rather than reproduced)
                        ├─ EH-aware local coalescing / cross-block copy propagation / redundant-cast
                        │   removal — each is a narrow, independently verified rewrite that is only
                        │   applied when it can be *proven* safe from the CIL itself, and is skipped
                        │   (falling back to a more conservative, already-verified form) otherwise
                        ▼
                 CIL method body: real locals, real branches, real exception handlers
                        │
                        ▼
                 rewritten assembly, standalone (no remaining dependency on the VM runtime)
```

Every rewrite tier follows the same discipline: build a candidate body, verify it independently
(stack-depth/type-safety checks, then an external CLR verifier), and only install it over the original
if verification passes — otherwise the method is left in its original, working, VM-backed form and
reported as such. Nothing is ever silently guessed.

## A concrete example

`TestCases/Program.cs` in this repo is original test fixture code, written to exercise specific
control-flow shapes (nested try/catch, rethrow, finally, without a `filter` clause, since this Agile.NET
version rejects `endfilter` at protection time):

```csharp
public static int RethrowWithoutFilter(int mode)
{
    LastRethrowTrace = 0;
    LastRethrowException = string.Empty;
    try
    {
        try
        {
            LastRethrowTrace = LastRethrowTrace * 10 + 1;
            if (mode == 0)
                return 10;
            if (mode == 1)
                throw new ArgumentException("inner");
            throw new InvalidOperationException("escape");
        }
        catch (ArgumentException)
        {
            LastRethrowTrace = LastRethrowTrace * 10 + 2;
            throw;
        }
    }
    catch (ArgumentException ex)
    {
        LastRethrowTrace = LastRethrowTrace * 10 + 3;
        LastRethrowException = ex.GetType().FullName + ":" + ex.Message;
        return 100 + ex.Message.Length;
    }
    finally
    {
        LastRethrowTrace = LastRethrowTrace * 10 + 4;
    }
}
```

After protecting this with Agile.NET and decompiling the protected output, that entire method is gone —
replaced with the VM dispatch stub:

```csharp
public static int RethrowWithoutFilter(int mode)
{
    return (int)CSVMRuntime.RunMethod("909aa5c1-5cd2-4983-9e2e-b6e55e5498f8", new object[1] { mode });
}
```

There is no way to read the original logic from this form — the switch/try/catch/rethrow/finally
structure, the exception types, even how many branches exist, are all opaque, held only in the `_CSVM`
resource and interpreted by the VM runtime at call time.

Running this tool against that protected assembly (`dotnet run -- TestCases.exe AgileDotNet.VMRuntime.dll
out.exe --ssa-phi`) reconstructs:

```csharp
public static int RethrowWithoutFilter(int mode)
{
    LastRethrowTrace = 0;
    string empty = string.Empty;
    LastRethrowException = empty;
    try
    {
        try
        {
            int lastRethrowTrace = LastRethrowTrace;
            lastRethrowTrace *= 10;
            lastRethrowTrace++;
            LastRethrowTrace = lastRethrowTrace;
            switch (mode)
            {
            case 0:
                return 10;
            case 1:
                throw new ArgumentException("inner");
            default:
                throw new InvalidOperationException("escape");
            }
        }
        catch (ArgumentException)
        {
            int lastRethrowTrace = LastRethrowTrace;
            lastRethrowTrace *= 10;
            lastRethrowTrace += 2;
            LastRethrowTrace = lastRethrowTrace;
            throw;
        }
    }
    catch (ArgumentException ex3)
    {
        int lastRethrowTrace = LastRethrowTrace;
        lastRethrowTrace *= 10;
        lastRethrowTrace += 3;
        LastRethrowTrace = lastRethrowTrace;
        LastRethrowException = ex3.GetType().FullName + ":" + ex3.Message;
        return 100 + ex3.Message.Length;
    }
    finally
    {
        int lastRethrowTrace = LastRethrowTrace;
        lastRethrowTrace *= 10;
        lastRethrowTrace += 4;
        LastRethrowTrace = lastRethrowTrace;
    }
}
```

(Decompiled with ILSpy; a compound `x = x * 10 + 1` shows up as three separate statements because that
is genuinely how the CIL evaluates it — the tool never invents higher-level expression folding it can't
prove from the bytecode.) The `if (mode == 0)` / `if (mode == 1)` chain in the source became a `switch`
here, because that is the concrete branch shape the VM bytecode actually encoded for this build — both
are correct, semantically equivalent CIL. The result is standalone: the output assembly has no remaining
reference to the VM runtime DLL, and the exact same exceptions, trace values, and messages come out at
run time as from the original source. It isn't pixel-perfect — a handful of methods across the wider
corpus still retain a small amount of decompiler-visible copy noise (tracked and explained in
`AgileDevirtualizer/DESIGN.md`'s "Status / roadmap" section) — but it is semantically exact and,
for the large majority of methods, close to source-grade readable.

## Building and running

Requires the .NET 8 SDK.

```
dotnet build AgileDevirtualizer/AgileDevirtualizer.csproj -c Release
dotnet run --project AgileDevirtualizer -- <protected.exe> <VMRuntime.dll> [output.exe] [flags]
```

Common flags (see `AgileDevirtualizer/DESIGN.md` for the full list and what each stage proves before
activating):

| Flag | Effect |
|---|---|
| *(none)* | Optimized CIL: dispatcher-loop elimination, strict EH-SSA cleanup. The default. |
| `--ssa-phi` | Adds multi-block SSA phi lowering (congruence-class slots / typed edge copies); installs a candidate only when it is strictly smaller/cleaner and independently verified. |
| `--cast-cleanup` | Removes `castclass`/conversion instructions proven redundant from local stack provenance and the real CLR type hierarchy — never a guess, never a hierarchy it can't resolve. |
| `--legacy-emission` | A straightforward, unoptimized lowering kept as a test-only oracle to diff against. |

`sample1`/`sample2` referenced throughout `DESIGN.md`/`VALIDATION.md` are the internal, non-public test
corpus used during development (real Agile.NET-protected third-party software, kept private for
obvious reasons) plus a public reverse-engineering practice crackme. They are intentionally not part of
this repository. `TestCases/` and `FaultCases/` are original fixtures written specifically to exercise
this project, protected locally with a licensed copy of Agile.NET, and are what the included
`scripts/*.ps1` validate against.

## Validation

Every claim above is checked mechanically, not just asserted — see [`VALIDATION.md`](VALIDATION.md) for
the full methodology: three success levels (lifted / builder-accepted / verified-correct), an external
CLR verifier pass, and runtime comparison against the known-source oracle across dozens of semantic
vectors including exceptional control flow (`leave`, nested `finally`, `rethrow`). The regression suite
that runs this against the private real-world corpus lives outside this repo; the scripts included here
(`scripts/validate-source-fixtures.ps1`, `validate-fault-fixture.ps1`, `build-fault-fixture.ps1`,
`validate-method-quality-report.ps1`) run the same methodology against the public `TestCases`/
`FaultCases` fixtures instead.

## Credits

Built on [AsmResolver](https://github.com/Washi1337/AsmResolver) (MIT) for all metadata reading, IL
manipulation, and CIL emission.

## License

[MIT](LICENSE).
