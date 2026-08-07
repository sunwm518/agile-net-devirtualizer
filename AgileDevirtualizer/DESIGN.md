# AgileDevirtualizer — Design

A **generic** devirtualizer for Agile.NET (SecureTeam) method virtualization. It reverses
virtualized method bodies back to normal CIL by *deriving everything from the actual
`AgileDotNet.VMRuntime.dll`* that a sample ships with — no hardcoded opcode tables, no
per-sample patches, no name-based handler matching, no non-generic heuristics.

## Why "driven by the runtime DLL"

Agile.NET ships a `AgileDotNet.VMRuntime.dll` alongside each protected assembly. That DLL
*is* the specification of the VM: it contains the opcode→handler map, the per-handler
operand-decoding logic, and the per-handler execution semantics. Different builds shuffle
the opcode map and rename everything, and emit many semantically-identical "polymorphic"
handler classes to defeat pattern matching. The only robust, generic strategy is to read
the truth out of that DLL every run. See `memory/agile-vm-architecture.md` for the RE facts.

## Pipeline

```
runtime DLL ─► RuntimeModel ─────────────► OpcodeMap (index→handlerType)
                    │                        HandlerInfo{ readMethod, executeMethod }
sample .exe ─► VMResource(_CSVM) ─► VMMethod{ token, localsBlob, codeBlob, ehBlob }
                    │
                    ├─ CodeStream: [count][uint16 opcodes...][operand blob]
                    │        for each opcode i: OperandDecoder runs handlerType[op].readMethod
                    │        (IL-interpreted against the real blob) → named operand values
                    ├─ LocalsDecoder(localsBlob)  → List<TypeSignature>
                    └─ EhDecoder(ehBlob)          → List<EhClause> (instruction-index ranges)
                    ▼
             DecodedMethod{ VMInstruction[], locals[], eh[] }
                    ▼
        HandlerClassifier: IL-analyze each handlerType.executeMethod → VmOp (a CIL opcode + how
        operands map). Classification is by BEHAVIOR of the execute IL, cached per handlerType.
                    ▼
             CilBuilder: emit CIL. Branch operands are instruction indices → resolve to labels.
             Rebuild locals, exception handlers, maxstack.
                    ▼
        Write patched module: replace each virtualized MethodDef body, drop VM plumbing.
```

## Components (namespaces under `AgileDevirtualizer`)

- **`Runtime`** — `RuntimeModel` loads the runtime DLL with AsmResolver, finds the abstract
  handler base (the type with two abstract methods `void f(BinaryReader)` and `void g(ctx)`),
  finds the opcode-registry type (static ctor that repeatedly calls `reg(typeof(X))`), and
  reads the **registration order** to build `OpcodeMap`. For each handler type it locates the
  read-method (the `void f(BinaryReader)` override) and execute-method (the `void f(ctxType)`
  override) via the MethodImpl / base-slot binding — never by name.

- **`Resource`** — `VMResource` scans manifest resources and parses the `_CSVM` table (it
  self-validates by consuming the stream exactly and checking tokens resolve). `LocalsDecoder`
  and `EhDecoder` per the RE'd formats.

- **`Decode`** — `CilInterpreter`, a small, faithful interpreter over AsmResolver CIL bodies,
  reused for two jobs: (1) `OperandDecoder` runs a handler's read-method against the operand
  blob so the *real* `BinaryReader.ReadXxx` sequence consumes bytes exactly as the runtime
  would, yielding operands keyed by the field they were stored into; (2) the classifier's
  abstract interpretation of execute-methods.

- **`Lift`** — `HandlerClassifier` maps a handler's execute-method to a `VmOp`. It abstractly
  interprets the execute IL over a symbolic model of the ctx (stack/locals/args/IP/return) and
  recognizes the effect as one CIL instruction (or a small fixed template). Recognition is
  structural and lives in one catalog keyed by observed effects, covering the CIL instruction
  set. Cached per handler type, so polymorphic duplicates each classify independently but
  correctly.

- **`Analysis`** — the semantic control-flow and production-emission layer. `LegacySemanticIrAdapter` projects the
  green `LiftedOp` stream into CIL-independent semantic operation families;
  `ControlFlowGraphBuilder` constructs basic blocks, typed normal/exception edges, formal
  `RegionPath` values, and exception regions. `ControlFlowGraphValidator` checks coverage and edge
  invariants. `AbstractState` and `WorklistAnalyzer` compute a finite forward fixed point over stack,
  locals, types, nullability, managed pointers and widening constants. `LegacyStateComparer`
  automatically contrasts each block exit with an opt-in structured snapshot from the legacy linear
  lifter, while `LegacyDifferenceClassifier` separates proven legacy-only surplus from semantic
  imprecision and possible CFG/worklist defects. `SemanticCfgEmitter` lowers the formal graph into a
  detached, validated body, and `SemanticEmissionController` installs it directly on the production path.
  Legacy comparison exists only in the test-only `LegacyOracleEmissionController`.

- **`Emit`** — explicit `--legacy-emission` uses `CilBuilder` to turn `DecodedMethod` into a `CilMethodBody`: creates one label per
  VM instruction, emits the classified CIL, rewrites branch/switch operands (instruction index
  → label), declares locals, and reconstructs exception handlers from index ranges.

- **`Cli`** — `Program` wires it together: input assembly + runtime DLL → output assembly.

## Non-negotiable rules

1. Opcode values, operand layouts, and handler semantics come from the loaded runtime DLL —
   nothing is hardcoded to a specific build or sample.
2. Handlers are matched by behavior, never by (randomized) name.
3. If a handler cannot be classified, we fail loudly for that method (and report it) rather
   than guessing — partial/incorrect output is worse than a clear "unsupported handler".

## Handler shape: block-fused (important)

Handlers are NOT 1-op-1-handler. Some are a single CIL op (br, brfalse, ldstr, nop), but many
encode a whole straight-line basic block ending in a (conditional) branch — e.g. op0 = `ldarg;
call; stfld; ret`, op2 = `ldloc; switch(table)`, op3 = `ldc; call; stloc; br`. So the lifter must
produce an ordered CIL *sequence* per handler, binding operand slots to the handler's decoded
fields. Two generations exist and are handled uniformly: modern (`sn0=`, 574 small fused handlers,
heavy polymorphic duplication) and classic (`lXU=`, ~11 large group handlers that internally
dispatch a family via a discriminator operand). The lifter classifies by the *behavior* of the
execute-method IL, driven by the structurally-identified `RuntimeVocabulary` — never by name.

## Status / roadmap

- [x] RE of the runtime (see memory + this doc)
- [x] **M1**: RuntimeModel + opcode map + VMResource — VERIFIED on both VMs (sample1 574 handlers/101
      methods; sample2 11 handlers/1 method). Registry found by validating the ldtoken'd types share
      a base with the two abstract handler slots.
- [x] **M2**: OperandDecoder (interprets each handler read-method IL against the real blob) + Locals
      + EH decoders — VERIFIED: all 101 modern + the classic method decode, operand blobs consumed
      exactly. Fixed a locals bug (CLASS/0x12 reads no token, unlike VALUETYPE/VAR/MVAR).
- [x] **M3a**: RuntimeVocabulary — structurally identifies stack push/pop/peek + ctx
      locals/args/IP/return/setLocal accessors + boxed-value type. VERIFIED on both VMs, matches RE.
- [ ] **M3b — CORPUS-COMPLETE, FRAMEWORK-OPEN**: the execute-method lifter fully lifts all seven
      checked-in protected builds: sample1 101/101, sample2 1/1, historical TestCases 3/3 and 6/6,
      TestCases 8/8, advanced TestCases 11/11, and FaultCases 1/1 (131 methods total). General new
      execute-handler shapes remain explicit unsupported cases until represented by real fixtures.
- [ ] **M4 — CORPUS-COMPLETE, FRAMEWORK-OPEN**: CilBuilder + writer accept sample1 101/101,
      sample2 1/1, TestCases 8/8, advanced TestCases 11/11 and FaultCases 1/1; every fully rewritten
      output is standalone. These are internal acceptance metrics; external verification and runtime
      oracles remain mandatory.
- [ ] **M5 — PARTIAL**: the advanced 11-method known-source TestCases output is PEVerify-clean and matches
      the source across a 46-vector semantic matrix, including native catch/rethrow. The devirtualized
      fault fixture is 1/1, standalone, PEVerify-clean and matches both source unwind paths. sample2 is
      fully devirtualized, PEVerify-clean, standalone and password-path validated. sample1 has an
      automated safe form/control/move/disconnected/synthetic-device/close/thread-cleanup matrix plus
      user-confirmed real-device operation; destructive device/service paths remain lab-only. See
      `../VALIDATION.md` and run `scripts/validate.ps1`.
- [x] **Observational CFG checkpoint**: formal semantic IR, typed CFG/EH regions, finite
      `AbstractState`, convergent worklist, and legacy-state comparison are active only under tests
      or `DEVIRT_DIAGNOSTICS_DIR`. All 25 advanced-fixture contradictions are classified as
      legacy-linear artifacts; none is currently transfer imprecision or a possible CFG/worklist
      error. The same exact regression audit now covers sample1's 101 methods/1,316 blocks and
      sample2's one method/seven blocks: both have valid, convergent graphs with zero transfer
      imprecisions, zero possible CFG/worklist errors, and zero unresolved surplus. Generic field and
      call result types are instantiated before entering the lattice.
- [x] **Semantic CFG oracle checkpoint**: the advanced fixture's 11 formal graphs lower into detached,
      internally validated CIL bodies that are structurally equivalent to the 11 accepted legacy
      bodies (opcodes, operands, locals, labels, branch/switch targets, EH regions and max stack).
      Semantic IR contains no concrete opcode hint: signedness, NaN ordering, overflow, primitive type, dispatch,
      prefix and exact operand encoding are explicit semantic attributes, and `SemanticCilLowerer`
      independently selects the concrete CIL form. The shadow body is owned by an unattached synthetic
      method and never replaces the real target body. The same strict test passes sample1 `101/101`
      and sample2 `1/1`, yielding a total independent-semantic baseline of 113 methods with zero
      structural differences. Targeted tests cover semantic-sensitive forms absent from the corpus.
- [x] **Controlled CFG activation checkpoint**: the former dual-build route proved that every fully
      lifted method could be selected by formal EH/leave/switch/backedge/merge or `StraightLine`
      properties and matched legacy exactly. It covered advanced 11/11, sample1 101/101 and sample2
      1/1, with standalone, PEVerify/runtime-validated outputs. This migration gate is retained as an
      oracle test, not as production control flow.
- [x] **Remove dual-build oracle from production**: the default path calls
      `SemanticEmissionController` directly and never constructs a legacy body. Failure keeps the original
      VM-backed method and is reported as `semantic-failed`; there is no silent fallback. `CilBuilder`
      remains reachable only through `--legacy-emission`, while exact 113/113 comparison remains in tests.
      The semantic-only outputs pass PEVerify/runtime gates, and sample1 is byte-identical to the manually
      validated all-CFG artifact.
- [x] **SSA/SCCP/DCE checkpoint**: explicit SSA definitions, uses, stack/local/argument phis, dominance
      and EH invariants pass the complete 113-method baseline. Verified SCCP, conservative DCE and CFG
      simplification identify 43 infeasible sample1 blocks, 41 constant guards and 41 finite cyclic
      dispatchers without name/token rules.
- [x] **Optimized CIL shadow checkpoint**: every one of the 41 dispatcher methods has a verified direct
      transition/state-slice rewrite. Reachable-block emission physically removes dispatcher blocks for
      non-EH methods. The shadow audit remains 113/113 and the optimized sample1 output adds no PEVerify
      errors over the lossless semantic baseline.
- [x] **Optimized CIL activation**: the optimized route is now the default after sample1 passed startup,
      device detection and close-with-X runtime checks. `--no-optimize` retains the lossless semantic
      rollback. ILSpy confirms all 41 dispatcher switches, all 161 `Math.Abs` scaffolding calls and all
      54 `goto IL_` artifacts are gone; five real domain switches remain.
- [x] **Typed straight-line SSA lowering**: exact metadata types resolve 9,905/10,019 sample1
      operation results and 652/652 conservative spill requirements. Minimal scheduling uses six
      actual spills and preserves the exact order of every observable or throwing operation. Detached
      lowering validates all 43/43 straight-line methods. `--typed-ssa` installs 14 smaller bodies
      beside 41 dispatcher rewrites and 17 strict EH bodies, giving 72 optimized methods total; the
      artifact remains 101/101, standalone, PEVerify-neutral and ILSpy-clean.
- [x] **SSA phi lowering (non-EH)**: `--ssa-phi` retains the independently verified congruence-slot
      lowering and adds explicit typed copies per executable edge. Copies on critical edges are
      emitted through synthetic split blocks; source-exit and target-entry placement is used only
      when the corresponding degree proves it unambiguous. `SsaEdgeCopyVerifier` independently
      reconstructs copy coverage, exact types and placement from SSA.
- [x] **Multi-block sample2 activation**: sample2 has seven live phi destinations, seven typed copies
      and three structural critical edges into its common exit. The deliberately conservative shadow
      body was 1,046 instructions; expression propagation/local coalescing reduced it to 708, UTF-16
      array reconstruction to 101, and alias/dead-local cleanup to 82, versus the 697-instruction
      lossless baseline. The final opt-in body is PEVerify-clean, standalone and passes the known
      password path. Activation is generic (`MultipleBlocks`, verified plans, structural-quality gate),
      never based on token or method name. The advanced fixture now selects two smaller methods and
      remains source-equivalent across all 46 vectors. sample1 remains byte-identical to the typed
      SSA checkpoint because edge activation is deliberately limited to multi-block methods.
- [x] **Run multi-block lowering after dispatcher rewrite**: the optional phi route rebuilds
      worklist, SSA, SCCP and DCE from the rewritten graph; it never reuses stale pre-rewrite edges.
      All 41 sample1 rewrites pass the second SSA verifier, 27 produce verified phi/edge plans, and
      23 structurally better coalesced bodies are selected. Three grow by one CIL instruction while
      removing two locals each; the remaining selections are smaller. Any secondary failure
      keeps the already verified dispatcher-pruned body. Selection uses graph/type properties only.
- [x] **EH-aware copy propagation and local coalescing**: a separate cleanup tier propagates
      exact-type aliases only inside one CIL basic block and single-assignment reference aliases
      into `System.Object` without moving their definitions. Branch targets and every EH boundary
      split the proof domain. Each candidate is emitted detached and reruns label, max-stack and
      type-safety verification; rejection keeps the verified EH SSA body. On sample1 8/17 methods
      remove 366 instructions, 141 locals and 116 casts. In `0x0600005C`, ILSpy drops from 104 to
      78 lines and from five object locals/twelve assignment casts to zero, while preserving both
      enumerator finally regions. The full 46-vector EH matrix and sample1 runtime probes pass.
- [x] **EH-aware expression scheduling**: adjacent single-use `stloc; ldloc` pairs are forwarded
      only when neither instruction is a control-flow/EH boundary and the local has exactly one
      definition and one use. No instruction or throwing effect moves; the value simply remains on
      the evaluation stack. Detached validation selects 8/17 methods and removes another 408 CIL
      instructions plus 204 locals. `0x0600005C` reaches 59 ILSpy lines with natural enumerator
      loops, versus 104 before EH cleanup. PEVerify, 46/46 and all sample1 probes remain green.
- [x] **Complete SSA type classification**: the reported 9,905/10,019 “exact” count hid a
      semantically important fourth category. All remaining 114 sample1 outputs are direct `ldnull`
      values represented by the polymorphic `Null` lattice element; none are `Conflict` or
      `Undefined`. All 652 values that require locals/spills have exact metadata types. Converting
      polymorphic null to `System.Object` would be less precise and unsafe for generic reference
      consumers, so the invariant is now 10,019/10,019 classified, not 10,019 forced-exact.
- [x] **Generic aggregate constants**: local-backed constant arrays are recognized for all twelve
      primitive element types. Exact `char[] -> String` and standard ASCII/UTF-8/UTF-16 LE/BE/UTF-32
      byte decodes fold only after byte-for-byte round-trip proof. Aliases, other consumers, malformed
      bytes, control-flow/EH boundaries and exhausted `#US` capacity retain the original valid CIL.
- [x] **Structural quality selection**: candidate choice measures instructions, locals, casts,
      aliases, blocks and spills. A lower weighted cost may admit tightly capped CIL growth; three
      sample1 and one advanced selections use that path. The SSA-phi route now selects 23
      post-dispatch sample1 bodies and three advanced phi/edge bodies without token/name rules.
- [x] **Token-addressed per-method C# quality audit**: the diagnostic route records typed-SSA,
      phi/edge and EH cleanup attempts without participating in selection, then decompiles each
      MethodDef directly through ILSpy metadata handles. The permanent JSON/Markdown report covers
      all 101 CIL bodies and 96 standalone C# member bodies, proves the regenerated sample1 artifact
      byte-identical, and ranks residual debt by visible C# plus exact CIL metrics. The actionable
      baseline is 9 EH data-flow, 7 managed-pointer and 8 exact-type/materialization methods;
      aggregate rejection counts are not treated as a cleanliness score.
- [x] **Fail-closed redundant-conversion cleanup**: `--cast-shadow` classifies every `castclass`,
      `box`, `unbox.any` and numeric conversion without changing the installed body.
      `--cast-cleanup` removes only fixed-point identities proven from local stack provenance:
      null/exact reference identity (including assembly scope), the universal
      `object`/`ValueType`/`Array` cases and exact
      non-overflow numeric identities. It never resolves a hierarchy, moves an instruction or
      crosses a branch/EH boundary; uncertain derived/interface/generic casts and all box/unbox
      checks remain. Structural quality selected 66/101 Release candidates and removed 1,814
      conversions. CIL casts fell 2,310->521; ILSpy C# casts stayed 429 while lines fell
      4,411->4,363 and aliases 463->429. The opt-in artifact is standalone, M5-equivalent and
      PEVerify-neutral at the known nine sample1 diagnostics; sample2 is PEVerify-clean and accepts
      the known password, and advanced remains PEVerify-clean and source-equivalent on 46/46.
- [x] **Safe sample1 M5 automation**: a reflection/IL-driven probe verifies form construction,
      required controls, movement, disconnected state, a synthetic populated device, close-with-X
      and background-thread cleanup against protected/default/SSA-phi builds. Destructive real-device
      actions remain outside automation and require an explicitly controlled lab environment.
- [x] **Cross-build corpus matrix**: seven generated runtimes cover Agile.NET 6.6.0.35 and 6.6.0.42,
      6..574 registered handlers, the compact 11-group and expanded layouts, and 131 protected
      methods with exact decode/full-lift invariants. The audit exposed and fixed duplicate-framework
      type resolution for reflective `newobj; throw` and now devirtualizes the fault fixture 1/1.
      Its protected input has a truncated native-resource directory; the writer removes only that
      proven-invalid directory, producing standalone PEVerify-clean output matching the ILAsm source.
      More product versions remain framework-open until real input/runtime pairs are added.
- [x] **EH entry-state model (observational)**: catch handlers, filter evaluation, accepted filter
      handlers, finally handlers and fault handlers have explicit CLI entry contracts. Filter code
      has its own `RegionZone.Filter`; exceptional dispatch enters `filterstart`, and a distinct
      `ExceptionFilterHandler` edge models successful `endfilter`. Catch/filter entries receive a
      fresh non-null `ExceptionObject` SSA definition (never a stack phi), while finally/fault enter
      with an empty stack. Catch exception values carry their resolved metadata type; filter values
      use the CLI `System.Object` stack type. The independent verifier passes the four real advanced
      EH methods and every current real-corpus method, plus synthetic filter/fault fixtures, and
      rejects unresolved catch metadata. This remains outside emission.
- [x] **Region-aware EH phi-copy legality (observational)**: every live phi input is classified
      from its source/target `RegionPath`. Exception dispatch uses the existing local/argument state
      and forbids inserted edge code; normal copies are allowed only across valid CLI transitions;
      copies whose `leave` unwinds a finally remain explicitly deferred. The audit found and fixed
      20 generic CFG edges that crossed an EH boundary but were labelled `FallThrough`; all current
      corpora now have zero illegal/unclassified copy transitions. No EH plan is emitted yet.
- [x] **Explicit EH continuations (observational)**: leave targets carry ordered inner-to-outer
      finally chains; rethrow retains its active catch and dynamic exception search; endfinally
      distinguishes pending-leave resumption from exception unwind; endfilter represents accepted
      handler and rejected search outcomes. Fault never resumes a normal leave. All corpus and
      synthetic filter/fault invariants pass; invalid rethrow/predicate shapes are rejected.
- [x] **SSA phi lowering (EH shadow)**: `EhSsaShadowPlanner` extends SSA liveness with every
      source-variable store and its transitive dependencies, because catch/finally can observe the
      last store before any throwing operation. Exact typed locals materialize operation results,
      exception objects and stack phis; lexical block order preserves EH ranges. Detached emission
      covers catch/finally/rethrow plus synthetic filter/fault, never mutates the target body, and
      fails closed on unsupported region/copy shapes.
- [x] **EH stack-phi type recovery (shadow)**: metadata-distinct primitive values are joined only
      when the CLI evaluation stack proves they share the same integral category. The real sample1
      `Boolean`/`Int32` merge now receives an exact `Int32` spill; all 17/17 sample1 EH methods emit
      internally verified detached bodies. Its four exact `Int32` phi copies are on non-critical
      normal edges whose source and target have identical `RegionPath`. The serialized candidate is
      PEVerify-neutral, and a generic reflection probe proves identical values for all 25 static
      fields written by `0x06000065`; strict activation therefore advanced to 15/17 at that checkpoint.
- [x] **EH function-pointer rematerialization**: direct `ldftn` values are modeled as
      verifier-sensitive ephemeral stack values, not ordinary `IntPtr` locals. The generic gate
      requires one use, the same block, an adjacent native-int constructor consumer and no receiver;
      `ldvirtftn`, phi/multi-use and cross-boundary forms fail closed. The three pointers in
      `0x06000044` and one in `0x06000242` now serialize as canonical `ldftn; newobj` sequences with
      no spill. A validation-only 17-method sample1 artifact remains PEVerify-neutral (9 vs 9).
      A dedicated loopback-only runtime fixture proves two `GotFocus` delegates, one started
      `ThreadStart`, and one Curl write callback that receives and decodes a locally generated JWE.
      Baseline and rematerialized bodies produce identical results, so the exact direct/adjacent/
      single-use shape is now active and sample1 reaches 17/17 strict EH methods. The permanent
      fixture discovers both targets structurally (`auto auto`), without method names or tokens,
      and runs against the normal production artifact.
- [x] **EH SSA external validation**: the validation-only artifact installs four EH SSA bodies in
      an isolated advanced-fixture copy. It is standalone, PEVerify-clean and source-equivalent on
      all 46 runtime vectors. This gate caught and permanently covers both an invalid end anchor and
      missing source-variable stores that internal max-stack/type checks alone did not detect.
- [x] **Strict EH SSA production route**: EH SSA is enabled by default and selects by semantic
      properties, never name/token. The initial runtime-proven tier accepts catch/finally with no
      evaluation-stack phi edge copies, plus the proven same-`RegionPath`, no-unwind edge-copy shape
      and adjacent direct single-use function pointers; filter/fault stay shadow-only. Any rejected method
      falls back automatically to the stable semantic emitter.
      `--eh-ssa` is an explicit equivalent of the default and `--no-eh-ssa` is the permanent
      rollback. The route activates 4/4 advanced EH methods and all 17 sample1 methods, keeps 101/101
      acceptance, and adds no PEVerify errors. Default and explicit outputs are byte-identical.
- [x] **EH cross-block copy propagation**: a fourth EH cleanup tier forwards a copy whose definition
      and every load cross a basic-block boundary, once every load is proven to sit in the identical
      exception-region nesting (no `leave`/`endfinally`/`endfilter` continuation is modeled — a
      mismatch simply rejects that candidate) and unreachable from any dynamic path that redefines the
      source first. Legality is decided by a dedicated instruction-level reachability search
      (`CrossBlockPropagationLegality`) that tracks, for every position, whether it is reached cleanly
      or only through a redefinition; a load reachable through even one tainted path is rejected. The
      candidate is verified on a fresh `CilMethodBodyCloner` clone rather than the already-emitted
      expression-scheduling body: calling `ComputeMaxStack` a third time on the same instance throws a
      spurious `StackImbalanceException` even with zero further edits, an AsmResolver-side
      non-idempotency that `CilRedundantCastShadowEmitter` already worked around the same way. On
      sample1, 10/17 EH methods improve, including both methods previously blocked at the
      single-basic-block coalescing tier (`0x06000026`, `0x06000027`, each losing 2 instructions and
      4 locals). Adversarial unit tests cover both rejection paths (an intervening redefinition
      reachable on one branch; a load sitting in a different exception region) in addition to the
      corpus audit. The full validation gate passes unchanged (sample1 PEVerify stays at 9, all 46+29
      semantic vectors and the M5 matrix pass) since the tier is part of the default EH SSA route.
- [x] **EH interference-based local coalescing**: a fifth EH cleanup tier merges CIL locals whose
      live ranges never overlap into one shared slot, independent of any copy instruction connecting
      them — the generalization that actually attacks the EH SSA shadow emitter's "one fresh local per
      stack-phi/spill value" shape by construction, rather than only removing pure-alias copies.
      `CilLocalInterferenceGraph` computes exact backward liveness at instruction granularity over a
      raw-CIL flow graph shared with the cross-block tier (`CilInstructionFlowGraph`, factored out of
      both), widened with a conservative edge from every instruction inside a try region to its
      handler's entry, and a `leave`-exits-`finally`/`fault` chain edge (`leave`→handler entry,
      `endfinally`→next exited handler or the leave's real target) modeling the implicit execution CIL
      never encodes as a branch. A local is eligible only when every reference to it is a plain
      `ldloc`/`stloc`; any local ever addressed via `ldloca` is excluded rather than reasoned about.
      **Two real corpus bugs were found and fixed before this shipped**: (1) a value staged before a
      `leave` that implicitly runs an enclosing `finally` was merged with a `finally`-local, corrupting
      a caught-and-rethrown exception's return value, because the leave/finally chain wasn't modeled
      yet — fixed by adding the chain edges above. (2) even with that fix, a nested
      try/finally-inside-try/catch shape (the sample1 Curl write-callback method) still corrupted a
      decoded response string; rather than chase further nested-region interactions one at a time,
      merging was restricted to locals whose *entire* live range stays inside one exception-region
      membership signature (`CilLocalInterferenceGraph.ConfinedEligibleLocals`, the same restriction
      `CrossBlockPropagationLegality` already used safely) — a local needing cross-region reasoning is
      excluded outright rather than trusted to the (necessarily incomplete) edge model. This cost only
      ~3% of the win (554→538 sample1 locals removed) and both bugs' regression tests pass. On sample1,
      16/17 EH methods improve; `0x06000027` falls from 155 CIL locals to 17, `0x06000026` from 143 to
      16. Adversarial unit tests cover all three safety rails (overlapping live ranges; an address-taken
      local; the leave/finally corruption shape) in addition to the corpus audit. Full validation gate
      passes with zero failures.
      **Known follow-up, found after shipping**: CIL locals collapsing (down to the low teens per
      method) does not translate 1:1 into cleaner ILSpy output. Decompiling `0x06000027` before/after
      showed unique C# variable names dropping from 136 to 15 — a real, large win — but ILSpy also
      emitted 49 literal `x = x;` self-assignment no-ops that did not exist before, roughly cancelling
      the line-count improvement (189→193 lines).
- [x] **Redundant-cast self-store cleanup**: root-caused the 49 no-ops above to one specific, fully
      generic shape: coalescing unifies a slot that used to be two locals of two related types, one
      narrowed into the other by a `castclass` that is now a same-type no-op — `ldloc X; castclass
      X's-own-type; stloc X`. `CilInterferenceLocalCoalescing.RemoveRedundantSelfStores` previously only
      matched a literally-adjacent `ldloc X; stloc X`; it now tolerates exactly this intervening
      same-type cast, deleting all three instructions (unconditionally safe: the cast can never throw
      against its own declared type, including null, and the net effect was already zero). Needs no
      cross-block reasoning, unlike the other tiers, since removing a true no-op changes nothing
      regardless of control flow. Result on `0x06000027`: self-assignments 49→0, C# lines 193→144, CIL
      casts 55→6, aliases 63→14; `0x06000026` shows the same pattern. Across the corpus, the "EH
      local/data-flow cleanup" weighted-debt bucket fell from 30,028 to 17,937, and both methods dropped
      out of the top-4 ranked offenders entirely. `RedundantCastRealCorpusTests`' sample1 floor moved
      1700→1600 (this fix legitimately removes some of what `--cast-cleanup` used to find, so its own
      remaining count is smaller — not a regression); `scripts/validate-cast-cleanup.ps1`'s matching
      floor was updated the same way. Full validation gate passes with zero failures.
- [x] **Hierarchy-aware redundant-cast cleanup**: `CilRedundantCastAnalyzer.IsAssignable` previously
      only proved a `castclass` redundant via exact type identity plus a few CLI-universal cases
      (`object`/`ValueType`/`Array`) — a real, deliberate limit ("hierarchy resolution is intentionally
      excluded"), leaving every safe upcast (a field declared `Label` passed where the inherited
      `Control.set_Size` is called, a control cast to an interface it implements like
      `ISupportInitialize`) unrecognized and therefore un-removable. Replaced that exclusion with
      `IsAssignableThroughHierarchy`, which defers to AsmResolver's own `TypeSignature.IsAssignableTo` —
      the exact same base-type/interface walk `CilTypeSafetyValidator` already trusts for verification —
      wrapped in the same fail-closed try/catch used everywhere else in this codebase for defensive
      resolution. Generic by construction: no hierarchy is hardcoded, any real CLR base-class or
      interface relationship the target framework can resolve is covered. One narrow gap found and left
      as-is (fails closed, not unsafe): `IsAssignableTo` on the small set of `CorLibTypeFactory`
      shortcut types (`String`, `Int32`, …) does not fully resolve their *own* interface list, so a
      cast from one of those specific types to an interface they implement stays unproven; ordinary
      class types (everything in the real corpus — WinForms controls, exceptions, etc.) are unaffected.
      Found via a colleague's manual dnSpy inspection of sample1's (fully virtualized, VM-reconstructed)
      `InitializeComponent`: every inherited `Control`/`ISupportInitialize` member access on a
      derived-typed field carried a redundant upcast. Result on that method (`0x06000067`): CIL casts
      283→1, C# casts 217→9, dropping it from rank #2 to rank #6 in the corpus ranking. Corpus-wide:
      sample1 cast-cleanup selects 71/101 methods (was 65) and removes 1,911 conversions (was 1,662);
      the "Residual alias/cast canonicalization" weighted-debt bucket fell from 39,758 to 23,830 (40%).
      Three adversarial unit tests (`RedundantCastHierarchyTests`) prove a base-class upcast, an
      interface upcast, and an unrelated-sibling-type cast (must stay `RuntimeChecked`) independently of
      the corpus. `RedundantCastRealCorpusTests` and `validate-cast-cleanup.ps1` floors raised to match
      (65→71 selected, 1600→1800 removed for sample1; 4→6 removed for sample2). Full validation gate
      passes with zero failures.

## How to run (current)

`dotnet run -- <input.exe> <VMRuntime.dll> [output] [--cfg-emission | --legacy-emission] [--no-optimize | --typed-ssa | --ssa-phi] [--cast-shadow | --cast-cleanup] [--eh-ssa | --no-eh-ssa] [--eh-ssa-validation-artifact | --eh-ssa-copy-validation-artifact] [--show-cfg-decisions]`

sample1 must be devirtualized with its **complete dependency set beside the input**: resolution
failures against the missing sibling DLLs change cross-module member widening, and the output then
keeps a VM runtime reference instead of being standalone. `scripts/validate.ps1` copies
`.validation-current/sample1-m5-clean88` into both the input and output directories for this reason.
Default prints opcode map + decodes every virtualized method (reports blob-consumption invariant).
