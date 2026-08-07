# Validation

The project uses three deliberately separate success levels:

1. **Lifted** — every VM instruction was translated to a candidate CIL sequence.
2. **Builder-accepted** — AsmResolver could compute max stack and write the candidate body.
3. **Semantically valid** — the written assembly passes an external CLR verifier and produces the
   same runtime result as known-good code.

Only level 3 is a correctness claim. In particular, `Devirtualized 101/101` reports level 2; it does
not by itself prove that all rebuilt bodies are semantically correct after metadata is rewritten.

## Fast regression tests

```powershell
dotnet test AgileDevirtualizer.Tests\AgileDevirtualizer.Tests.csproj -c Release
```

These cover seven independently generated Agile.NET runtimes: sample1, sample2, the four staged
`TestCases` builds and the protected `FaultCases` build. The corpus contains versions 6.6.0.35 and
6.6.0.42, the 574-handler expanded layout and the compact 11-group-handler layout. All 131 protected
methods decode and lift completely. Builder/runtime floors remain separate correctness claims; a
floor is only a regression guard, not a semantic-validity claim.

## Full validation gate

```powershell
powershell -ExecutionPolicy Bypass -File scripts\validate.ps1
```

The full gate:

- builds and runs the automated tests;
- rebuilds the known-source `TestCases` project in an isolated directory;
- builds the reflection-based `TestCasesInvoker` semantic oracle;
- executes the source-only `--extended` comparison/null/arithmetic cases and checks their exact results;
- checks the sample1/sample2/TestCases acceptance floors, including advanced control flow at `11/11`;
- runs the .NET Framework SDK's `PEVerify.exe` on source, protected, and rewritten artifacts;
- executes source, protected, and devirtualized TestCases with redirected input;
- compares protected/devirtualized happy-path output with the known-source output;
- evaluates the compatibility fixture across 29 semantic vectors and the advanced fixture across 46;
- requires default semantic CFG emission to activate all `11/11` advanced methods without building legacy, then
  rebuilds once with `--legacy-emission` and repeats PEVerify plus all 46 semantic vectors;
- requires default strict EH SSA to install exactly four advanced and all 17 sample1 methods, then proves
  the default artifacts byte-identical to explicit `--eh-ssa` artifacts;
- rebuilds advanced and sample1 with `--no-eh-ssa`, checks their pre-EH selection counts and repeats
  standalone, PEVerify and the 46-vector advanced runtime matrix;
- checks that rewriting PEVerify-clean sample2 does not introduce metadata errors;
- requires fully rewritten sample1, sample2, and both TestCases outputs to be standalone;
- requires a zero-success sample2 run to copy the input byte-for-byte;
- executes every protected `TestCases` path after a full rewrite, including `CheckArrayLengthIndex`;
- rebuilds sample1 with `--ssa-phi` and requires it to be standalone, PEVerify-neutral against the
  optimized baseline and ILSpy-clean, while proving 23 post-dispatch SSA selections and three
  explicitly bounded-growth structural-quality decisions;
- rebuilds the advanced fixture with `--ssa-phi`, requires three installed phi/edge methods (one
  bounded-growth decision), and re-runs all 46 semantic vectors against the CLR source;
- rebuilds sample2 with `--ssa-phi`, requires strict `ssa-edge` selection, standalone output,
  PEVerify-clean CIL and the observable UI state produced by a known valid password;
- devirtualizes the real Agile.NET `fault` fixture 1/1, then requires standalone output, PEVerify 0
  and exact source-oracle results on normal completion and exceptional unwind;
- runs the offline function-pointer fixture and the safe sample1 lifecycle/device/error-path matrix
  against protected and rewritten artifacts.
- builds an isolated `--cast-cleanup` artifact, requires 101/101 and standalone output, compares its
  token-addressed CIL/C# metrics, repeats PEVerify and M5, validates sample2's known password, and
  checks the advanced fixture against all 46 source vectors.

## SSA phi lowering (`--ssa-phi`)

Multi-block lowering now has two independently verified forms: congruence-class slots and explicit
typed copies attached to executable edges. Critical copies are routed through synthetic split blocks;
non-critical copies use source exit or target entry only when CFG degrees make that placement unique.
On sample1 the phi route rebuilds analysis after dispatcher removal and selects 23 verified
post-dispatch SSA bodies. Three are accepted with one extra CIL instruction because they remove two
locals and lower the structural cost; the resulting artifact intentionally differs from the
typed-straight-line checkpoint.

Coverage remains clean under `SsaPhiLoweringVerifier`; edge-copy coverage and placement are separately
checked by `SsaEdgeCopyVerifier`. sample2 moves from 697 lossless instructions to 82 after expression
propagation, local coalescing, exact aggregate reconstruction and alias cleanup. Its seven live phi
destinations use seven typed copies, and all three structural critical edges are split. `--ssa-phi`
installs it through the structural-quality gate. The advanced fixture installs three phi/edge bodies,
remains PEVerify-clean and matches the source on all 46 vectors.

Rejections are explicit shapes, never silent gaps: `has two needed phis in one congruence class`
(1 advanced method), and `has an infeasible normal edge` (34 sample1 methods that the
dispatcher/constant-branch route owns).

## Multi-input semantic oracle

`TestCasesInvoker` loads a selected `TestCases.exe` through reflection, so the same executable tests
can target the source, Agile.NET-protected, and standalone devirtualized assemblies without changing
or reprotecting the fixture. Its full 46 vectors cover true/false/equal/reversed comparisons, negatives,
zero markers, `NaN`, infinity, all null/reference branches, zero and negative divisors, byte limits,
exact remainder, unchecked Int32 overflow, dense switches, caught exceptions, early returns, and
observable `finally` side effects, plus loop backedges, continue/break through finally, divergent
merge states, filtered exceptions in the source oracle, nested catch/rethrow, and escaping throws.

The advanced devirtualized assembly must match the original source on all 46 vectors. Agile.NET 6.6 itself
has one isolated protection-time semantic drift: `CompareNumericPaths(..., NaN, ...)` returns `True`,
while the original CLR code and recovered native CIL return `False` because ordered comparisons with
`NaN` are false. The gate records this explicitly and fails if the protected assembly differs from
the source on any other vector.

sample1 PEVerify counts are reported as diagnostics, not treated as an ordering metric: its protected
input is already heavily unverifiable and replacing 101 bodies changes how far PEVerify can progress.
With the complete dependency set, the current audited counts are `183` for the protected input and
`9` for the rewritten output. Token-level grouping attributes all nine remaining diagnostics to five
methods that were never virtualized; none belongs to the 101 rebuilt method bodies.

## Writer policy

- A zero-success run copies both the target and its VM runtime byte-for-byte.
- The CLI refuses to overwrite the runtime path used as input. If a rewritten target still needs a
  visibility-adjusted runtime, emit it into a separate staging directory and copy the validated
  output package deliberately.
- Partial outputs with a normal TypeDef layout use AsmResolver `PreserveAll`, keeping raw VM metadata
  operands stable while new imports are appended.
- VM operand strings are projected against the preserved `#US` heap before emission. If a new
  string would start beyond `ldstr`'s 24-bit heap-offset limit, the lifter reconstructs it through
  `char[]` and `String(char[])`; this prevents invalid `0x71xxxxxx` tokens while preserving the
  exact UTF-16 contents.
- If a module places a nested TypeDef before its enclosing TypeDef, AsmResolver cannot preserve that
  table order. That module uses a coherent standard rebuild instead of a partially preserved,
  ownership-corrupting table set. Full token remapping for this unusual layout remains future work.
- If a protected input advertises a native-resource directory that provably ends mid-record, the
  writer clears only that unparseable directory. Valid native icons, manifests and version resources
  are preserved. This converts the otherwise non-loadable Agile `fault` input into valid rewritten CIL.

The command exits with code 1 when any correctness gate fails. Failure artifacts are retained under
the printed temporary directory; successful artifacts are deleted unless `-KeepArtifacts` is used.

At the current audited baseline the full gate passes. Both fully devirtualized TestCases outputs are
PEVerify-clean and runtime-equivalent to the known source. The advanced fixture rebuilds all 11
protected methods, is standalone, and matches all 46 vectors, including loop backedges, merge-state
paths, nested catches, native `rethrow`, finally and leave.

This does not mean destructive application-wide M5 is complete: sample1's protected baseline is
already heavily unverifiable. Its safe matrix is now automated, however: form construction, required
controls, movement, disconnected-device state, a synthetic populated device, close-with-X and cleanup
of background threads must match between protected, default and SSA-phi builds. The 101-method output
is standalone and the user also confirmed startup, real-device detection, normal operations and close.
START/jailbreak/restore/delete and external-service paths still require an explicitly controlled lab
device/backend; the automatic gate deliberately does not invoke them. sample2 is fully devirtualized,
standalone, PEVerify-clean and validated through its known correct password path.

## Fixture provenance

`TestCases/Project11.controlflow.cls` is the compatibility Agile.NET 6.6.0.42 GUI project. Its protected
output is `TestCases/bin/Release/net48/Secured-controlflow`, and it selects exactly:
- `CheckArrayLengthIndex`;
- `BuildDictionary`;
- `GuidRoundTrip`;
- `CompareNumericPaths`;
- `CheckReferenceNulls`;
- `ComputeI4Arithmetic`;
- `SwitchWithFinally`;
- `SwitchWithCatchFinally`.

The comparison/null/arithmetic cases cover:

- `CompareNumericPaths` for signed integer, floating-point, byte/I4, equality and ordering paths;
- `CheckReferenceNulls` for branch-style null checks and direct reference equality;
- `ComputeI4Arithmetic` for mixed byte/Int32 add, multiply, subtract and remainder operations.

The known-source expectations are exercised with:

```powershell
TestCases\bin\Release\net48\TestCases.exe --extended
```

The control-flow cases cover:

- `SwitchWithFinally`, a dense switch with normal, early-return, goto-case and default paths leaving
  through a `finally` region;
- `SwitchWithCatchFinally`, a dense switch inside a nested `try/catch`, all enclosed by `finally`,
  with normal, caught-exception, early-return and default paths.

The source and emitted output contain native `switch`, `leave`, `catch`, `finally`, and `endfinally`
CIL. This compatibility fixture is audited at `8/8`: the protected input's one pre-existing PEVerify
diagnostic in `BuildDictionary` is reduced to zero, the rebuilt output is standalone, and it matches
the source across all 29 vectors. The older `Secured` and `Secured-next` fixtures remain untouched as
historical checkpoints.

## Advanced control-flow fixture (active)

The advanced source adds four C#-expressible stress methods beyond the active fixture:

- `LoopContinueBreakFinally`: loop backedges plus `continue` and `break` leaving through `finally`;
- `MergeBackedgeStates`: different values merge at every branch and loop header;
- `FilterAndRethrow`: true/false filters, caught rethrow, escaping exception, exact type/message and
  observable effect order;
- `RethrowWithoutFilter`: the same rethrow/finally stress isolated from filter opcodes.

The compiled source contains real backedges, `leave`, `filter`, `endfilter`, `rethrow`, `finally`,
and `endfinally` CIL and is PEVerify-clean. Seventeen new oracle cases extend the full source matrix
from 29 to 46 vectors. Agile.NET 6.6.0.42 refuses to virtualize `FilterAndRethrow` because its
`endfilter` opcode is unsupported. That method therefore remains a source-only CLR oracle.
`TestCases/Project12.advanced-controlflow.cls` selects the other three methods (including
`RethrowWithoutFilter`) and writes only to
`TestCases/bin/Release/net48/Secured-advanced-controlflow`. The protected fixture runs all 46 oracle
vectors. The devirtualizer rebuilds its 11 virtualized methods as native CIL, including the two catch
regions, `rethrow`, and finally in `RethrowWithoutFilter`; the result is standalone, PEVerify-clean,
and matches the source on all 46 vectors. This `11/11` result is now an active regression floor.

C# cannot emit a CLR `fault` clause. `FaultCases/FaultCases.il` therefore provides a separate,
source-controlled ILAsm fixture with a real `fault` region. `FaultCasesInvoker` verifies both normal
completion (fault must not execute) and exceptional completion (fault state, exception type and
message). `FaultCases/ProjectFault.controlflow.cls` writes its future protected output only to
`FaultCases/bin/Release/net48/Secured-fault`.

Agile.NET reports a successful build for the current fault project, but its protected
`FaultCases.dll` is rejected both by the CLR loader (`E_INVALIDARG`) and by PEVerify because its
native-resource directory is truncated. It remains valid VM transformation input. The devirtualizer
now recovers the constructed exception type through the already-loaded framework assembly, lifts and
emits the method `1/1`, and removes only the unparseable native-resource directory while writing. The
standalone result is PEVerify-clean and matches the source oracle exactly: normal completion returns
`10` without executing fault, while exceptional completion preserves `InvalidOperationException`,
message `fault-case`, and the observable fault state `77`.

## Intermediate diagnostics

Set `DEVIRT_DIAGNOSTICS_DIR` before running the devirtualizer to create a per-method diagnostic
directory. The opt-in dump contains:

- `01-vm-instructions.txt`;
- `02-lifted-ops.txt`;
- `03-blocks.txt` and `04-cfg.dot` (the formal observational CFG; not used for lifting);
- `05-stack-states.txt`;
- `06-eh-regions.txt`;
- `07-emitted-il.txt`;
- `08-status.txt`;
- `09-semantic-ir.txt` (semantic operation families plus legacy provenance);
- `10-cfg-validation.txt` (block/edge/exception-region counts and invariant results);
- `11-worklist-states.txt` (fixed-point entry/exit state and processing count per block);
- `12-legacy-comparison.txt` (automatic block-exit comparison with the legacy linear shadow state);
- `13-ssa.txt` (definitions, uses, phi nodes and SSA invariant results);
- `14-sccp.txt` (value lattice, executable edges and folded terminators);
- `15-dce.txt` (live instructions, side-effect roots and constant replacements);
- `16-cfg-simplification.txt` (removed blocks, folded branches and finite cyclic dispatchers);
- `17-eh-entry-model.txt` (catch/filter/finally/fault entry contracts and SSA exception objects);
- `18-eh-phi-copy-legality.txt` (per-edge RegionPath legality for live phi inputs);
- `19-eh-continuations.txt` (leave/finally chains, rethrow and both endfilter outcomes).

Diagnostics do not participate in lifting or emission and are disabled by default. The formal
analysis model contains basic blocks, typed branch/switch/leave and exception edges, nested
`RegionPath` values, and decoded EH regions. All 11 advanced methods pass its invariants, including
loop backedges, merge points, nested catch/rethrow, and finally. Its finite `AbstractState` lattice
tracks stack shape, CLI value families, nullability, managed pointers, sparse local types and
constants that widen at merges. The forward worklist converges on all 11 methods without stack-shape
conflicts; backedge blocks are demonstrably reprocessed, catch entries receive one non-null exception,
and finally entries receive an empty stack.

EH entry state is now represented explicitly rather than inferred only from a generic exceptional
edge. A filter has two distinct entries: its evaluation region and the accepted filtered handler;
both receive separate CLI-created exception-object SSA values. `RegionPath` distinguishes the filter
zone from its handler zone. Catch entries resolve the exact catch metadata type, whereas filter entry
values use the CLI object-reference stack type. Finally and fault entries are required to have an
empty evaluation stack. `ExceptionEntryModelVerifier` checks entry inventory, edge kind, region path,
stack depth, non-null SSA definition, type and the absence of evaluation-stack phis. It is green over
the four EH methods in the protected advanced fixture, all current sample1/sample2 methods, and
synthetic filter/fault cases; a negative fixture proves unresolved catch tokens are rejected. The
model and diagnostic are observational and do not change the emitted assembly.

Region-aware phi-copy analysis is also observation-only. It classifies each live phi input as a
normal emitted copy, implicit existing-variable state on CLI exception dispatch, deferred until the
`leave`/`finally` continuation is explicit, or illegal. Normal edges are checked against the
ECMA-335 entry/exit rules for protected blocks, filters and handlers; exceptional edges never receive
inserted copy code. This audit exposed 20 formal edges that left EH regions but were still labelled
lexical `FallThrough` (19 in sample1 and one in advanced). They are now classified generically as
`Leave` whenever `RegionPath` loses a frame, matching the CIL already emitted at that boundary.
After the correction, advanced has 130 normal/method-entry copies, 27 implicit exception-entry
variable states, 14 finally-dependent leaves and zero illegal transitions. sample1 has 4,388, 70,
11 and zero respectively; sample2 has seven normal copies and no EH/deferred/illegal case. Negative
tests reject entry into the middle of a try, normal entry into a handler, branch exit without leave,
and leave out of filter/finally/fault code.

EH terminator continuations are explicit as well. Each `leave` records its final target and the
inner-to-outer sequence of finally regions that must execute first. `rethrow` is tied to its active
catch/filter handler but deliberately continues through dynamic CLR exception search. `endfinally`
records whether it can resume specific pending leaves and always preserves exception-unwind
continuation; a fault handler is forbidden from resuming normal leave. `endfilter` has two distinct
outcomes: the accepted filtered handler and rejected dynamic exception search. Advanced contains 11
leave continuations (nine unwind at least one finally), one rethrow and four endfinally sites.
sample1 contains 47 leaves (eight with finally unwind) and seven endfinally sites; sample2 has no EH
continuation. Synthetic filter/fault tests cover semantics Agile.NET 6.6 cannot protect, while
negative tests reject rethrow outside catch and a non-int32 endfilter predicate. This model remains
detached from emission.

EH SSA lowering is separated into shadow, validation-artifact and strict production gates.
`EhSsaShadowEmitter` always builds a detached body and verifies that the installed target body is
unchanged. Its emission closure retains every source-variable store, not only DCE-live stores: this
is required because an exception can expose the local state established before a throwing
instruction. Store inputs, phis, pure constants and operation definitions are recovered
transitively; exception objects and non-constant results use exact typed locals.
Catch/finally/rethrow pass on the four protected advanced methods, while synthetic filter/fault
tests verify their entry stacks, `FilterStart` and `endfinally` metadata.

EH stack-phi type recovery is now complete for the audited sample1 corpus in shadow. It does not
weaken the metadata type lattice: only evaluation-stack phis may canonicalize CLI-equivalent
integral categories (`Boolean`/small integers/`Int32`, `Int64`/`UInt64`, and native integers). The
real mixed `Boolean`/`Int32` phi is assigned an exact `Int32` spill. All 17 sample1 EH methods build,
verify and emit detached bodies without changing their targets. The four copies in `0x06000065` are
all exact `Int32` assignments on non-critical normal edges: two remain inside the same catch try-path
and two remain outside EH. A dedicated serialized candidate adds no PEVerify errors relative to its
same-build baseline. `MethodStateProbe` explicitly invokes both bodies and hashes only the 25 static
fields written by the method; all 25 hashes are identical. Production therefore admits this generic
same-`RegionPath`, no-unwind shape and advanced activation to 15/17 sample1 EH methods at that
checkpoint.

Direct EH function pointers are no longer typed or serialized as ordinary `IntPtr` spill locals.
`EhFunctionPointerShadowModelBuilder` recognizes only a structural, token-independent proof: direct
`ldftn`, no receiver, one use, same block, adjacent consumer, and an exact native-int constructor
parameter. The three values in `0x06000044` and the one in `0x06000242` are rematerialized at that
consumer, producing canonical `ldftn; newobj` sequences. `ldvirtftn`, phi/multi-use and any
cross-instruction/block form fail closed. Installing all 17 EH shadow bodies in a separate sample1
validation artifact is PEVerify-neutral against the default artifact (9 diagnostics versus 9), and
the original target bodies remain untouched by shadow emission. Dedicated runtime coverage now
exercises all four values without external traffic: two real `GotFocus` subscriptions and one
started background `ThreadStart` in `0x06000044`, plus a Curl write callback in `0x06000242` against
a loopback HTTP server. The server receives one 801-byte request and returns a locally generated JWE;
both baseline and rematerialized bodies decode the marker and exit successfully. This exact generic
shape is therefore production-enabled, bringing strict sample1 EH activation to 17/17.
The permanent validation gate runs `FunctionPointerProbe <artifact> auto auto`: both methods are
discovered from their signatures and `ldftn` shapes, not from names or metadata tokens. It then
checks the two live event subscriptions, the background thread and the complete loopback Curl/JWE
round trip on the normal production artifact.

Post-dispatch SSA is now a distinct verified tier under `--ssa-phi`. After dispatcher and constant
branch removal it rebuilds worklist, SSA, SCCP, DCE, type inference and phi/edge plans from the new
graph. On sample1 all 41 rewrites pass this second analysis, 27 are fully lowerable, and 19 are
strictly smaller after edge-copy coalescing (47 additional CIL instructions removed in total). The
other 14 fail closed on explicit managed-pointer/address/prefix or exact-type-conflict requirements;
they retain the verified pruned dispatcher body. No method or metadata token participates in this
selection.

EH local cleanup is production-enabled through a detached fail-closed candidate. Exact aliases may
coalesce only inside one CIL basic block; reference-to-`System.Object` aliases additionally require
a single-assignment, non-address-taken source. This prevents propagation over branch targets or EH
boundaries and does not schedule any throwing operation. Every candidate reruns label, max-stack and
type-safety checks. Eight of 17 sample1 EH methods pass and remove 366 instructions, 141 locals and
116 casts; nine retain their prior verified bodies. ILSpy's `0x0600005C` output improves from 104 to
78 lines, with object locals 5→0 and assignment casts 12→0. PEVerify remains 9, the advanced fixture
remains 46/46, `0x06000065` preserves all 25 written-field fingerprints, and all four function-pointer
runtime checks remain green.

EH expression scheduling is a second detached tier. It forwards only an adjacent `stloc; ldloc`
pair whose local has one definition/use and whose two instructions are not branch targets or EH
boundaries. This changes neither effect order nor exception timing. Eight methods forward 204 values,
removing another 408 instructions and 204 locals. `0x0600005C` decompiles to 59 lines with ordinary
`while (MoveNext())` enumerator loops; PEVerify remains 9 and every runtime/semantic gate passes.

The operation-result type audit is complete: sample1 has 9,905 exact metadata types and 114
polymorphic `Null` results, all emitted by direct `ldnull`. There are zero `Conflict` and zero
`Undefined` operation results, and all 652 spill-required values are exact. Therefore the correct
coverage is 10,019/10,019 semantically classified; coercing those 114 nulls to `System.Object` would
reduce correctness for string/array/delegate/generic reference consumers.

Aggregate constant recovery is structural and exact. `CilConstantArrayPattern` recognizes local-backed
one-dimensional constants for all twelve primitive element types, including default zero elements and
duplicate in-range writes. Consumers fold `char[]` through the exact `String(char[])` constructor and
`byte[]` through the exact standard ASCII, UTF-8, UTF-16 LE/BE or UTF-32 encoding singleton. A byte
sequence is accepted only if encode(decode(bytes)) reproduces the original bytes. Aliases, unrelated
uses, branch targets, EH-boundary crossings, malformed encodings and unavailable `#US` capacity all
fail closed and retain the valid array form. The sample2 password body remains 82 instructions and
runtime-equivalent.

Optimization selection uses `CilStructuralQualityGate`, not only instruction count. Its metrics count
CIL instructions, locals, casts, adjacent aliases, basic blocks and SSA spills. A candidate must lower
the weighted structural cost; instruction growth is capped at `max(4, ceil(baseline/20))`. Current
SSA-phi results select 23 post-dispatch sample1 bodies, including three one-instruction-growth bodies
that each remove two locals, and three advanced phi/edge bodies, including one bounded-growth body.
PEVerify, ILSpy, the 46-vector matrix and the safe sample1 runtime matrix remain green.

The token-addressed per-method quality audit is observational and runs with
`scripts/audit-sample1-method-quality.ps1`. It asks the installed ILSpy engine to decompile each
`MethodDef` directly, so obfuscated names and overloads are never used for association. The report
combines C# lines/object locals/casts/aliases/temporary locals/control-flow nesting with exact CIL
quality and every structured SSA/EH rejection reason. It regenerates `--ssa-phi` in a temporary
directory and requires SHA-256 identity with the preserved `structural-quality` artifact before
publishing `reports/sample1-structural-quality/method-quality.json` and `.md`. Five accessors or
compiler-folded members retain complete CIL metrics but have no standalone ILSpy method text;
96/101 have both layers. The permanent gate fixes the actionable baseline at nine EH
local/data-flow cleanup methods, seven managed-pointer methods and eight exact-type/materialization
methods without influencing emission.

## Redundant conversion cleanup (`--cast-shadow`, `--cast-cleanup`)

The conversion analyzer is opt-in. `--cast-shadow` records a detached candidate and classification
but installs the ordinary semantic body; within the same build its serialized output is byte-identical
to the route without cast analysis. `--cast-cleanup` installs the candidate only when label, max-stack,
type-safety and structural-quality validation all pass. The pass deletes instructions in place and
iterates to a fixed point; it never reorders effects.

The initial proof domain is intentionally narrow and resolver-free: null, exact static type identity
(including assembly resolution scope),
reference-to-`object`, boxed value-to-`ValueType`, array-to-`Array`, and exact non-overflow numeric
identity. `box`, `unbox.any`, overflow, width/signedness/precision changes, uncertain hierarchy or
generic substitutions, and every branch/EH boundary remain untouched. This avoids both suppressed
runtime exceptions and lazy-metadata side effects.

The Release gate selects 66/101 sample1 candidates and removes 1,814 conversions. Against the same
SSA-phi build, CIL instructions fall 17,587->15,773 and CIL casts 2,310->521. ILSpy's explicit C#
cast count is unchanged at 429, while C# lines improve 4,411->4,363, aliases 463->429 and temporary
locals 328->321. The permanent report is under `reports/sample1-cast-cleanup/`. The final sample1
artifact keeps the nine pre-existing PEVerify diagnostics, passes the protected M5 safe lifecycle,
and is standalone. sample2 is standalone, PEVerify-clean and accepts its known password. The advanced
fixture is PEVerify-clean and matches the source on all 46 vectors. The automated suite is 186/186.

The cross-build corpus audit loads seven independently generated runtime binaries and fingerprints
their handler IL without consulting names or tokens. It covers Agile.NET 6.6.0.35 and 6.6.0.42,
runtime sizes from 6 to 574 registered handlers, the compact 11-group-handler runtime and six expanded
build-specific vocabularies. Exact version, method count, handler binding, operand-stream consumption
and full lifting are permanent tests for all 131 protected methods. Different hashes are recorded as
different generated shapes, not misreported as different product versions. This is evidence for two
versions and both observed handler architectures; broader Agile.NET version support still requires
real additional protected/runtime pairs.

`--eh-ssa-validation-artifact` is a fail-closed serialization gate, not a production fallback. It
installs exactly those four EH bodies in an isolated advanced-fixture copy. The result is 11/11,
standalone, PEVerify-clean and identical to the source across all 46 runtime vectors. The external
gate found two defects that the internal validator could not: a final `nop` anchor allowed method
fall-through, and removed `stloc` operations left finally/loop state stale. The permanent fixes are
an unreachable `ldnull; throw` end sentinel and the store-complete EH emission closure.

Strict EH SSA is the default production route. Selection is generic: valid/convergent CFG and SSA,
verified entry/continuation/RegionPath models, exact types, catch/finally clauses, direct adjacent
single-use function-pointer rematerializations only, and either no stack-phi copies or only runtime-proven copies on
normal non-critical edges with identical source/target `RegionPath`. Filter/fault remain shadow-only
until a protected runtime fixture can exercise their serialized form. Rejection automatically uses the stable
semantic emitter. `--eh-ssa` explicitly selects the same route; `--no-eh-ssa` disables only this
tier and restores the pre-EH semantic route. Default and explicit artifacts are byte-identical on
advanced and sample1. The route activates all four advanced EH methods and passes PEVerify plus
46/46; on sample1 it activates all 17 methods, preserves 101/101 and standalone output, and remains at
the known optimized baseline of nine PEVerify diagnostics. sample2 has no EH, therefore follows
its unchanged normal route and remains PEVerify-clean with the valid-password runtime path.

The comparison is intentionally honest about the two different observations. In the current
advanced fixture, 58 block exits are equivalent, one is compatible through an unknown value, and 25
differ. `LegacyDifferenceClassifier` assigns all 25 to the legacy-linear observation category: six
are compound-handler shadow-stack residue, two cross consecutive VM indices that have no normal CFG
edge, and 17 propagate an already-contaminated linear state. There are zero semantic-transfer
imprecisions and zero possible CFG/worklist errors in this fixture.

The classification is conservative. Only legacy-only surplus stack entries over a structurally valid,
converged and precise formal state enter the legacy category. An unmodelled semantic operation is
reported as transfer imprecision; a known type/local contradiction, a formal-only stack entry, an
invalid graph or a non-convergent state is reported for CFG/worklist audit. These results are findings,
not acceptance failures. `CilBuilder`, method acceptance, and emission do not consume the CFG or
worklist and remain on the green legacy path.

The same observation-only audit is active over the real corpus. sample1's 101 methods produce 1,316
blocks: 155 equivalent, 35 compatible, 1,083 legacy-linear artifacts, and 43 structurally dead blocks
with no incoming edge. Its artifact causes are 705 compound-handler shadow stacks, 336 propagated
linear carries, and 42 carries through an unreachable sequential instruction. sample2's one method
produces seven blocks: four equivalent and three legacy-linear artifacts (two compound shadow stacks
and one propagated carry). Both corpora have zero semantic-transfer imprecisions, zero possible
CFG/worklist errors, zero unresolved precise surplus, valid CFG invariants, convergent worklists, and
no stack-shape conflict. Generic call/field signatures are instantiated through `GenericContext`;
this prevents open `!0`/`!!0` signatures from being reported as false concrete-type contradictions.

Diagnostic directory components use a restricted ASCII projection because real obfuscated metadata
names can be invisible Unicode whitespace or end in Windows-invalid spaces. The metadata token remains
the unique identity, so this filename normalization has no semantic effect.

## Independent Semantic CFG emitter

`SemanticCfgEmitter` consumes the formal CFG and creates
a new `CilMethodBody` owned by a synthetic method that is not attached to the target module. It rebuilds
VM-index labels, branch/switch targets, locals, protected-region exits and exception handlers, then runs
label verification, max-stack calculation and the internal CIL type-safety validator. The emitter itself
returns a detached body; `SemanticEmissionController` installs it only after all semantic gates pass.

Semantic IR no longer contains a `CilOpCode` or any equivalent lowering hint. It represents opcode
meaning with independent signedness, ordered/unordered floating-point comparison, checked/unchecked overflow, primitive operand type, direct/virtual
dispatch, prefix kind and implicit/short/inline operand encoding. Argument and local references are also
normalized into semantic references. `SemanticCilLowerer` is the only reverse mapping from those
attributes to concrete CIL. The temporary `LiftedOp` adapter is an input boundary; neither the lowerer nor
the semantic emitter reads an accepted legacy body while constructing its result.

`ShadowCfgEmitterTests` exercises all 11 virtualized methods in the advanced fixture. For every method it
first builds the accepted legacy body, creates and validates a separate shadow body, verifies that
`target.CilMethodBody` still references the legacy body, and compares initialization, max stack, locals,
every opcode and normalized operand, branch/switch target indices, and every exception-region boundary.
The current independent-semantic oracle checkpoint is `11/11` structurally equivalent with zero
differences. This test remains detached and deliberately builds legacy only inside the test suite.

The same strict audit is now a permanent regression test over the real corpus. sample1 produces
`101/101` detached, validated and structurally equivalent shadow bodies; sample2 produces `1/1`.
Across these 102 methods there are zero lowering failures, zero structural differences and zero
instances where shadow emission changes the installed body. Together with the advanced fixture,
the current independent-semantic emission baseline covers 113 methods. Targeted round-trip tests also
cover signed and unsigned arithmetic/comparisons, every checked integer conversion, typed array access,
all supported CIL prefixes, short/inline/implicit operands and every conditional/leave encoding, including
forms absent from the current corpus. This remains an in-memory test only: no
shadow body is serialized by the audit itself.

## Semantic-only default emission

The default route is now semantic-only. `--cfg-emission` remains an explicit equivalent, while
`--legacy-emission` selects the separate legacy builder for diagnosis or rollback. Every fully lifted method is a
candidate; formal graph properties classify it as exception/leave/switch/backedge/merge or `StraightLine`,
never by method name or metadata token. A candidate must have a valid CFG, a converged worklist with
consistent entry-stack shapes, and an independent semantic lowering for every operation and terminator.

`Devirtualizer.Run` does not call `CilBuilder` on this route. `SemanticEmissionController` analyzes the
graph, builds and validates the detached semantic body, then installs it directly. Analysis, validation or
emission failure restores the original VM-backed body, rejects that method honestly and increments
`semantic-failed`; it never falls back silently to legacy. `CilBuilder` is reachable only through explicit
`--legacy-emission`. `--show-cfg-decisions` prints the decision and detected feature set per method.

Legacy remains an oracle only in `ShadowCfgEmitterTests`, `RealCorpusShadowCfgEmitterTests` and the two
negative `LegacyOracleEmissionController` tests. These keep exact 113-method structural comparison without
placing dual-build work on the production path.

Current default results are:

- advanced fixture: 11 candidates, 11 semantic bodies activated, four strict EH SSA bodies,
  zero semantic failure;
- sample1: 101 candidates, 101 activated, 58 optimized bodies including all 17 strict EH SSA bodies,
  zero semantic failure;
- sample2: one candidate, one activated, zero semantic failure.

On the advanced fixture the feature counts cover four exception-region/leave methods, two switches,
three backedge methods, six merge-point methods and five `StraightLine` methods. The serialized default
output is standalone, PEVerify-clean and matches the source across all 46 semantic vectors. Dedicated
negative tests prove that a semantic-emission exception retains the original VM body, while the isolated
legacy-oracle tests still detect an exception or structural difference.

The dual-build dependency is therefore removed from production.

## SSA optimization checkpoint

The observation-only optimization pipeline now passes all 113 audited methods: sample1 `101/101`,
sample2 `1/1`, and advanced control-flow `11/11`. `SsaGraphBuilder` creates explicit definitions,
uses and phi nodes over locals, arguments and the evaluation stack. `SsaVerifier` checks dominance,
definition-before-use, phi predecessor arity, stack agreement and EH entry shapes. SCCP then reaches a
verified fixed point without executing arbitrary calls; the only currently whitelisted pure framework
call is `System.Math.Abs`. DCE preserves calls, memory effects, allocations, checked arithmetic,
division/remainder and prefixes unless their removal is independently proven safe.

The sample1 audit identifies 43 infeasible blocks, 41 folded constant guards and 41 finite cyclic
dispatchers. Dispatcher recognition is structural: the switch selector is a phi whose executable
backedge inputs are finite constants, and every selected arm returns through the cycle. It does not
inspect method names or metadata tokens. All 41 dispatchers have a verified pure state-calculation
suffix and an exception-region-safe direct transition.

The optimized semantic emitter is now the default. It rewrites dispatcher transitions and constant
guards, then uses a reachable-basic-block layout for methods without EH. `--no-optimize` selects the
lossless semantic route for rollback, and any method that does not pass every optimization gate also
uses that lossless route automatically. Current sample1 results are 101/101 accepted and standalone;
41 methods are optimized. The
optimized assembly has the same nine PEVerify diagnostics as the lossless semantic output, down from
183 in the protected input, so the optimization adds no verifier regression. sample2 remains 1/1,
standalone and PEVerify-clean.

ILSpy 9.1 decompilation confirms that method `0x0600001D` is now the direct three-statement thread
setup sequence after its field assignment; the `for (;;)` loop, dispatcher `switch`, state local,
`Math.Abs` calls and constant guard are absent.

The whole-assembly ILSpy quality gate compares lossless and optimized C# under identical settings.
`Math.Abs` scaffolding falls from 161 occurrences to zero, `switch` from 46 to five, `while (true)`
from 90 to 11, and decompiler `goto IL_` labels from 54 to zero. The five retained switches are real
domain logic, and the 11 retained infinite loops are real enumeration/polling loops. Run this gate
directly with `scripts/audit-sample1-ilspy.ps1`; the full `scripts/validate.ps1` invokes it as well.

The first genuine SSA-to-CIL lowering gate started with 26 spill-free sample1 methods. Exact metadata
type propagation now extends that gate to all 43 straight-line methods. It resolves 9,905/10,019
sample1 operation results and all 652 conservative spill candidates needed by this tier; unresolved
values never fall back to `object`. The minimal scheduler actually needs only six typed spills across
the 43 methods because constants and initial variables are rematerialized and a value is spilled only
for multiple live uses or effect-order preservation.

Detached typed lowering validates 43/43 methods. Compared with lossless semantic CIL, 22 bodies
change, 14 become smaller, three become larger, and the net reduction is 16 instructions. The
`--typed-ssa` opt-in installs only the 14 strictly smaller bodies, raising sample1 optimization from
58 to 72 methods while leaving equal/larger bodies on the existing emitter. The resulting assembly is
101/101, standalone, has the same nine PEVerify diagnostics as the default optimized baseline, and
keeps every ILSpy quality gate (`Math.Abs=0`, five domain switches, 11 real infinite loops,
`goto IL_=0`). The default remains unchanged until this opt-in artifact passes the manual runtime
smoke test. The next lowering checkpoint is phi edge copies and critical-edge splitting.

The new semantic-primary sample1 artifact, built without a legacy body, is byte-for-byte identical to
the previously validated all-CFG artifact (`SHA-256
A4277860D3E49D8D59F98845976C95E6B960C5712E94812917EA086586AD4A55`). Therefore the manually confirmed
startup, device detection and close-with-X result applies directly to the semantic-only output.
