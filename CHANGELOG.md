# Changelog

All notable changes to this plugin. Format: Keep a Changelog; versioning: SemVer.

## Unreleased

### Added

- 2.2.0: timer captures are profiled as an on-CPU time share; unsupported cases fail
  with a cause and proposed alternatives. A timer-based capture (`AMDuProfCLI collect --config
  tbp`, the only sampler on hosts without IBS or `CYCLES_NOT_IN_HALT`) is detected from its
  `CPU_TIME` event column; every `profile --by` view reads it, `METRIC` names the measures it
  lacks once, `READ` carries the top row's 95% binomial interval, and `ACHIEVED` reports per
  thread. `cpu_seconds` is not derived: timer ticks undercounted measured CPU time by up to 13%
  at 1 ms and 31% at 10 ms. `profile --time-filter` and `translate --ascii` on a timer capture,
  a session with no recognized sampler, and a `collect` whose `CYCLES_NOT_IN_HALT` AMDuProfCLI
  rejects now exit 2 with `error: <cause>` and one runnable `ALTERNATIVE:` line per option;
  nothing switches mode on its own (issue #190).

- Session symbol cache: `profile` keeps the symbol, public-symbol, PDB-choice and derived
  function-range artifacts in a per-session DuckDB database keyed by the capture's module
  identity, the queried RVAs, the on-disk image state, the tool builds and the search
  configuration. Repeated symbolizing scopes in one session reuse the cached tables with the
  original evidence text replayed; a changed binary, PDB, tool or scope misses and re-derives.
  The capture database stays read-only, the cache degrades to the uncached path on a lock or
  error, and there is no cross-session reuse or eviction yet (issue #45).
- `profile --by module [--json]`: one row per normalized module path with `samples`,
  `sample_share`, `time_share` (mode-dependent), `tag_to_retire_share` (dump with a non-null tag
  column), `Module.isSystemModule` and `cpu_seconds` (`samples × interval / core_frequency` for a
  cycle interval, omitted with its reason for a work/fetch interval or an unavailable frequency).
  The classification comes from `Module.isSystemModule` and is `NULL` when the export has no such
  column; `v_module_flags` matches both the full path and the basename. This makes the module
  rollup, the third-party rule and absolute CPU time readable from supported output without
  ad-hoc `cpu.db` SQL (issues #25, #26).
- `SYMBOL_COVERAGE` header line in `profile` (and JSON): the scoped samples that resolve to a
  non-empty `Function.name`, each module with unresolved samples and its unresolved share, and
  whether that module is `partial` or has `no named functions`. When a module has no names the
  line says the samples cannot be attributed below module/RVA and names the supported path, so a
  third-party module without a PDB is reported at module/RVA instead of sending the user into a
  hand-written PE or `.pdata` mapping (issue #27).
- `VERSION` in `profile`, `collect` and `translate`: the version from the nearest
  `.claude-plugin/plugin.json` plus the skill directory that produced the output, falling back to
  a built-in version for a loose skill copy, so output can be matched to the right docs
  (issue #28).

### Changed

- The profile pipeline is faster: the dump is parsed once into a `TEMP TABLE`, its time-share
  columns are cached as a validated Parquet copy, line and instruction views bind only for their
  own scopes, symbolization runs in parallel, function ranges are derived in a process pool, and
  public-symbol enumeration is reused within a run. Output is unchanged on the supported paths,
  with one deliberate stricter behavior: a nonzero `llvm-pdbutil` exit is treated as an
  enumeration failure even when it printed a valid Public Symbols section (the base ignored the
  exit code), so fold labels can be unavailable where the base emitted them. The first run on a
  capture pays the one-time Parquet copy build; later runs reuse it. The performance work is
  tracked in issue #19; measurements are recorded in the issue and PR records, not in the
  repository.
- Breaking: `profile` replaces `--pdb-file`, `--pdb-dir`, `--debug-file-dir` and
  `--fallback-debug-path` with repeatable `--symbol-path` (a symbol/debug file or a search
  directory, probed by the tool) and adds repeatable `--image-path` (a module image file or a
  directory searched by module basename). `translate` replaces `--pdb-dir` with repeatable
  `--symbol-path`. Callers updating from 2.1.0 must rename the flags; the next release is a
  major version (issue #38).
- `SKILL.md` has a worked "where did CPU time go?" example for an attached, cycle-controlled IBS
  capture: confirm the mode and scope, rank processes by `sample_share`, roll modules up with
  `profile --by module`, then read instructions with `profile --by instruction --json` (top 20)
  only when the resolved hot RVA needs context, and stop at the symbol boundary when
  `SYMBOL_COVERAGE` shows no named functions (issues #25, #26, #29). The reference gives the
  module fields, the third-party rule and the absolute CPU-time conversion.
- `NEXT` is the minimum path: from `process` it lists `module` and the instruction JSON call, and
  from `module` only the instruction JSON call, instead of every granularity.
- The worked example has an explicit deliverable and stop contract (module rollup with
  `isSystemModule` and `cpu_seconds`, `SYMBOL_COVERAGE`, hot RVA), names `VERSION` as
  authoritative, defines third-party as `Module.isSystemModule = false` and reports the dominant
  non-workload dependency separately, and points the quickstart at `profile --by process` first.
- Repository layout: the plugin source is now `plugin/` (the marketplace entry points at it);
  maintainer-only tests, fixtures and the timing harness live under `tests/` and `bench/`,
  outside the plugin source. No runtime behavior changes (issue #42).

## 2.1.0 — 2026-11-08

### Added

- Instruction context: `profile --by instruction --json` adds a `context` object to the first 20
  instruction rows in the table's impact order. Each block decodes forward from the nearest safe
  PE start at or below the hot RVA — an export, a PDB public, a `.pdata` runtime function or the
  code-section start, within a 1 MiB cap — and reports up to 32 instructions before and after the
  hot RVA, in ascending RVA, each with its raw sample count, its per-instruction `sample_share`
  fraction (the row's denominator and mode-specific meaning, not a second scale), and optional
  `llvm-symbolizer` frame-0 location, IAT import name and aggregated IBS OP fields. The block
  names its anchor and build identity: a nonzero PE `CheckSum` matching the capture verifies the
  build, a mismatch omits it, and no matching evidence is emitted as `identity: "unverified"` with
  a warning. A missing module, unsafe anchor, non-boundary hot RVA, unavailable LLVM tool or
  failing optional query omits the block with a stable reason instead of guessing; an omission
  made after the module was examined carries the same `build` object, so an unverified build or
  size mismatch is visible on the omitted row. The `<other instructions>` row carries none. Each
  anchor is decoded once for every row under it, and Markdown output is unchanged.
- `context_help`: a single top-level JSON object, emitted once after `legend` and before `rows`,
  that documents the context's fields, every omission reason, and how to read the sampled
  instruction and the IBS evidence. It defers unit, scale and denominator to the existing
  `legend` rather than defining a second scale. It states that the 20-row cap counts row slots
  (an omitted row still consumes one), that `instruction` may retain objdump's nearest-symbol
  decoration while `symbol` is the frame-0 name, and that IBS values are AMD-encoded counts or
  histograms, not decoded meanings. The `IbsTagToRetCtr` aggregate uses the
  `tag_to_retire_share` policy: unsigned decimal integer cells only, each clipped at 65535, the
  16-bit field's maximum, with NULL, negative, fractional and exponent cells excluded.

## 2.0.1 — 2026-11-08

### Fixed

- Attached captures no longer overcount `time_share`: DeltaTick gaps are partitioned by thread
  (`PID`, `TID`) instead of by `CPU_Number`. A thread that migrates between CPUs leaves a gap on
  every CPU it visited, and the per-CPU estimator summed those overlapping intervals, so the
  weighted total could exceed the capture span (454.203 s over a 39.386 s span, 11.5x, on the
  issue #23 capture) and reverse the ranking. System-wide captures keep the per-CPU partition.
  `ACHIEVED` counts the same contexts, so same-TID threads of different attached processes no
  longer merge.
- The dump-wide `SANITY` check for an attached capture now judges thread coverage, never a
  capacity of `elapsed x CPUs`, which was meaningless for a single-thread process and hid the
  overcount. A sample outside the recorded span is an error; `OK (attached; dump-wide)` reports
  the processes, TIDs, busiest TID's samples and covered gap time, CPUs visited and thread-time
  total, and still prints when every thread has a single sample.
- The `COLUMNS`/`READ` legend, the `TIME_SHARE` and `WEIGHTS` headers, and the JSON
  `legend.columns.time_share` / `legend.impact.estimate` state the `(PID, TID)` partition and that
  a thread's gaps include off-CPU time, and name `sample_share` as the CPU-cycle share and the
  better ranking for a cycle-controlled capture.

### Changed

- Docs qualify `time_share` as the impact ordering for system-wide captures and describe the
  attached partition; `references/reference.md`'s "10 s on 16 CPUs is about 160 s of weight"
  normalization is marked system-wide only.

## 2.0.0 — 2026-11-08

### Breaking

- Profile share columns are renamed and emitted as fractions 0.0-1.0 instead of percentages:
  `pct_samples` -> `sample_share`, `pct_time` -> `time_share`, `pct_cycles` ->
  `tag_to_retire_share`. `samples` is unchanged, while the `AGREEMENT` field keeps its
  human-readable percentages. Multiply an old `pct_samples` or `pct_time` by 0.01 to get
  `sample_share` or `time_share`. For `pct_cycles`, multiply by 0.01 only if every
  `IbsTagToRetCtr` cell in the capture is at most 65535; above that the new clip changed the
  denominator, so recompute `tag_to_retire_share` from the dump.
- `sample_share` states what a sample represents in each mode: the supported PMC cycle event is
  the busy core-cycle share (halted excluded); any other PMC event is not established; IBS OP
  cycle-controlled is the core-cycle share, not wall time; IBS OP op-count is the dispatched-op
  frequency share; IBS fetch is the fetch-sample frequency share (fetch path unverified). None is
  a per-operation cost.
- `time_share` is a time share estimated from gaps, not unqualified impact. Idle/wait is charged
  to the ending sample, the first sample per CPU is ignored (no gap before it), and NULL sorts
  last.
- `tag_to_retire_share` is the share of tag-to-retire cycles summed over sampled ops (AMD tag at
  dispatch to retirement, queue/stalls included); it is a total, not per-op latency.

### Added

- `profile` prints a short three-line legend with every result. `COLUMNS` states the fraction unit
  once, the mode-specific `sample_share` label, the `time_share` and `tag_to_retire_share` labels,
  the `attribution` definition when the scope emits it, and any absent column with the reason; the
  detailed definitions stay in the `METRIC`, `TIME_SHARE` and `TAG_TO_RETIRE_SHARE` header lines. `READ` states which column ranks where
  time went, that `sample_share` is not a per-op cost, that `tag_to_retire_share` is total
  tag-to-retire cycles (higher = more wait), and that the `<other ...>` row is last, not ranked.
  `NEXT` joins full runnable calls with `&&`, each keeping the session, the
  `--pid`/`--image`/time-filter scope and a non-default `--top`, with the last call adding `--json`
  to `--by instruction`.
- The JSON `legend` is machine-readable: `share_unit` (`fraction`), `share_scale` (`1`),
  `denominators`, `columns`, `absent`, `impact` (`order_by`, `gap_weighted`, `estimate`),
  `remainder_last` and `next`.
- `test_output_legend.py` covers PMC, an unsupported PMC event, an unsampled cycle event, IBS OP
  cycle-controlled, IBS OP op-count, IBS fetch, tagless, empty-tag and all-zero-tag dumps,
  fraction sums and range, ordering agreement with `views.sql`, the `<other ...>` remainder,
  runnable NEXT calls and the tag-cell exclusion rules.

### Changed

- Header fields `PCT_TIME` and `PCT_CYCLES` are now `TIME_SHARE` and `TAG_TO_RETIRE_SHARE`.
- The SQL share macro is `share(part, whole) = part / NULLIF(whole, 0)`, and the dump gap column
  `weight` is documented as the DeltaTick gap in nanoseconds, charged to the later sample.
- `references/validation.md` figures for these columns are fractions.

### Fixed

- `tag_to_retire_share` clips `IbsTagToRetCtr` at 65535, the 16-bit field's maximum, instead of
  131070. A value above the field maximum is charged 65535; NULL and non-integer cells are excluded
  from the denominator. The validation fixture and a new test cover the clip.

## 1.0.9 — 2026-11-07

### Fixed

- An unelevated capture that requests OS-mode samples no longer omits every kernel-mode sample
  silently. OS mode is requested for both capture events: the cycle spec passes `user=1,os=1`, and
  the IBS event samples user and OS by default. `collect` appends `kernel-mode (OS) samples are
  omitted without elevation` to its unelevated warning for either. `profile` prints a
  `KERNEL_COVERAGE` header line when the applied sampler requested OS mode and the whole capture
  has no kernel-image sample; it names the sampler's bit (`os`, `opOs` or `fetchOs`), reports an
  empty capture as such, and names elevation only conditionally. Kernel images are classified by
  `ModuleInstance.loadAddress` in the kernel address range, with a basename fallback for exports
  without that table (`.sys`/`.ko`, `ntoskrnl.exe`, `ntkrnlmp.exe`, `ntkrnlpa.exe`, `ntkrpamp.exe`,
  `hal.dll`, `vmlinux`, `vmlinuz`, `[kernel.kallsyms]`): `Module.isSystemModule` is true for
  user-mode `ntdll.dll`, and a suffix test for `hal.dll` also matches user-mode `marshal.dll`. The
  check shares the ACHIEVED whole-capture scan, covers the capture before scope and time filters, so
  a user-only scope cannot trigger it, and is suppressed when the session records a translate
  `--time-filter`, because the resolved dump may hold only that window. Evidence: the unelevated
  capture had 21,489 samples and none in a kernel image, while the elevated capture of the same
  event had 45,489 kernel samples in 67 images; translating that raw capture unelevated preserved
  them, so the loss is at capture time.

### Changed

- Documentation states the kernel-coverage limitation explicitly in `SKILL.md`,
  `references/spec.md` and `references/reference.md`: `os=1` is applied and encoded but an
  unelevated capture contains no kernel-mode samples, and kernel coverage requires an elevated
  capture. It explains that `KERNEL_COVERAGE` is a whole-capture check computed before
  `--image`/`--pid`/`--time-filter`, that it never refers to elevated user processes, and that the
  capture-time note and the profile-time field report the same limitation.
  `references/reference.md` records that the raw metadata has no elevation or kernel-mode toggle
  and that the check is content-based, not privilege-based.

## 1.0.8 — 2026-11-07

### Fixed

- `SANITY` no longer lets a dump-wide late-coverage verdict stand in for the report's scope. The
  dump-wide check compares the capture end against the last sample of every process, so an
  `--image`/`--pid` report whose own population stopped early still printed `OK` when an
  unrelated process sampled late (a 75 s capture with a `--pid` scope that ended at 60 s, for
  example). When `--image`/`--pid` or `--time-filter` narrows the report, `SANITY` now appends a
  `scoped coverage (<scope>)` verdict: the scope's last sample against the end of its window
  (the recorded span clipped to the profile time-filter window), `WARN` when the gap exceeds the
  scope's own sampling cadence. The dump-wide verdict is labeled `dump-wide across all processes`
  and the scoped one names its scope, so neither can be read as the other. Attached captures keep
  `OK (attached; dump-wide)` and get no scoped verdict (a missing `systemWide` counts as
  attached); the empty-scope warning is unchanged.

### Added

- `test_sanity_scope.py` builds a synthetic two-process capture whose scoped process stops at
  1.9 s while the dump continues to 10 s. Before the fix `--pid 100` printed
  `OK: 11.890 s of core time ...`; after it prints the dump-wide `OK` followed by
  `scoped coverage (--pid 100): WARN: the last sample in scope is 8.100 s before the scope window
  end at 10.000 s`.

## 1.0.7 — 2026-11-07

### Fixed

- `translate` refuses an `--out-dir` that already holds `cpu.db`, `callstack.db` or an ASCII
  dump instead of silently translating into it. The native translate appended to the surviving
  database, so reusing a directory doubled the sample count (4,369 to 8,726 on the `pmc-1ms`
  capture). `--force` replaces the generated files and the copied session inputs before
  translating, leaving unrelated files untouched, so a repeated translate is idempotent.

## 1.0.6 — 2026-11-07

### Fixed

- `ACHIEVED` no longer warns on a capture whose per-CPU average is diluted by idle CPUs. It now
  reports the busiest sampling context's cadence (median running `DeltaTick` gap for a dump,
  samples/s for PMC) and the number of active contexts, and the below-10% warning is based only
  on that context. The per-CPU average stays in the line, labeled as the whole-capture figure it
  is. An intermittent attached thread whose running gaps are at the requested interval no longer
  warns. `profile` uses `TID` as the context for attached captures and `CPU_Number` for
  system-wide ones; `v_dump` now exposes `tid`.

### Changed

- Documentation states the corrected picture: the collector delivers about 1,000/s on a busy CPU
  at a 1 ms request, the old 14/s and 92/s figures were averages over every CPU in the capture,
  and uProf's interval bounds (IBS 50,000-134,217,727 cycles, PMC at least 25,000 cycles) constrain
  the request rather than the delivered rate.

## 1.0.5 — 2026-11-07

### Fixed

- Dump sanity: samples outside the recorded span raise their own error naming those samples,
  instead of claiming core time exceeds a bound it does not; a recorded `translate --time-filter`
  is checked against its `[T1, T2)` window, so a window that starts after capture start no longer
  reports a false inconsistency.
- `ACHIEVED` on PMC captures counts `UnifiedSampleSeries` event-column samples over the whole
  capture, not the `--image`/`--pid` scope, and takes the CPU count from `coreId`, so it reports
  the per-CPU rate and the below-10% warning instead of zero samples and a claim that no rate is
  derivable.
- `translate --ascii` prints `ACHIEVED` counted from the dump it wrote, and says the rate is
  reported at profile time when it writes no dump.

### Changed

- Documentation matches the shipped checks: the `SANITY`/`ACHIEVED` header fields and failure
  modes in `SKILL.md`, the sanity, achieved-rate, anchoring and view descriptions in
  `references/reference.md`, and the validation record, including the attached capture's 39.682 s
  elapsed and the PMC and translate evidence. `anchor` states that `--freq` defaults to 10 MHz
  because `session.uprof` records no QPC frequency.

## 1.0.4 — 2026-11-07

### Changed

- The plugin icon is redrawn as a heat-mapped flame graph: each block's colour is sampled from
  its exclusive share of the block width, from faint yellow through orange to crimson, and the
  micro sign takes a colour just above mid-heat. The vector master ships as `icon.svg` alongside
  the `icon.png` raster.

## 1.0.3 — 2026-11-07

### Added

- Plugin icon: a flame-graph mark whose layout derives from golden-ratio divisions of the icon,
  with the micro sign set in Open Sans Regular — the typeface AMD uProf ships and uses for it.

### Changed

- Description now reads "built on AMD uProf"; the README states the plugin is not affiliated
  with or endorsed by Advanced Micro Devices.

## 1.0.2 — 2026-11-07

### Added

- MIT `LICENSE` (root) and the `license` field in the plugin manifest.

## 1.0.1 — 2026-11-07

### Changed

- `references/spec.md` aligned with the shipped behaviour: the `anchor` command, the `SANITY` and
  `ACHIEVED` header lines, and the contract that a delivered sample rate below the requested
  interval is reported rather than assumed.

## 1.0.0 — 2026-11-07

Initial packaging of the `amd-uprof` skill as a Claude Code plugin.

### Added

- `anchor` command: maps a workload's `QueryPerformanceCounter` reading onto capture-relative
  seconds, with the capture's UTC start where derivable. Negative values are attach latency.
- `ACHIEVED` header on `profile`: sample count, capture window, CPUs and achieved samples/s per
  CPU against the requested interval, with a warning below 10% of the ideal.

### Changed

- The dump sanity check no longer rejects good captures for per-CPU boundary gaps. It errors only
  on genuine inconsistency (core time exceeding the implied span, or a sample beyond it), reports
  the boundary gaps and the worst CPU, and distinguishes attached captures, whose coverage is
  limited to the CPUs the target ran on.
- `references/reference.md` documents the capture-clock derivation, the sanity semantics, the
  measured sampling cadence, and the limits of nearest-export attribution for symbol-less DLLs.

### Fixed

- Attached IBS captures were rejected by the sanity check with a ~28% mismatch because the
  denominator assumed every CPU was sampled for the target's whole lifetime.

