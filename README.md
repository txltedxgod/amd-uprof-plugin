<p align="center"><img src=".claude-plugin/icon.svg" width="128" alt="amd-uprof plugin icon"></p>

# amd-uprof plugin

AMD uProf profiling for Claude Code. Capture CPU time on AMD Zen, symbolize it, and answer
where the cycles go — with shares by process, function, source line or instruction.

## What it does

- Captures with AMD uProf's CLI: PMCx076 `CYCLES_NOT_IN_HALT` cycle sampling, system-wide or
  attached to PIDs; IBS OP sampling with an op-count or cycle-controlled interval. IBS fetch
  dumps can be translated and profiled but are not a capture choice.
- Symbolizes with llvm-symbolizer: PDB data on Windows, DWARF on Linux, down to file/line and
  instruction attribution. ICF-folded addresses are labelled shared instead of being credited
  to one name.
- Profiles by process, function, source line or instruction. Shares are fractions 0.0-1.0.
  `sample_share` states what a sample counts in that capture mode (busy core cycles for the
  supported PMC cycle event, core cycles for cycle-controlled IBS OP, dispatched ops for
  op-count IBS, fetch samples for IBS fetch); `time_share` is a time share estimated from gaps,
  partitioned by CPU for a system-wide capture and by thread (`PID`, `TID`) for an attached one (a
  migrating thread is counted once; for cycle-controlled IBS the fixed-cycle sample share is the
  CPU-cycle share and the better ranking), not unqualified impact; `tag_to_retire_share` is
  tag-to-retire cycles summed
  over sampled ops, a total, not per-op latency. The three are never conflated, and a three-line
  `COLUMNS`/`READ`/`NEXT` legend says so with every result.
- Queries the capture in DuckDB, with the schema and views shipped as `tools/views.sql`.
- Anchors a workload's QueryPerformanceCounter reading to capture-relative seconds; a negative
  value is attach latency, not the workload's own start.
- Prints `SANITY` and `ACHIEVED` before the shares: the dump's provenance against the capture
  span, and the rate actually delivered against the requested interval. When `--image`/`--pid`
  or `--time-filter` scopes the report, `SANITY` also states whether that scope sampled near the
  end of its own window, separately from the dump-wide verdict.

## What it is good for

- Cycle-based hot spots: what burns CPU and where, at function, line and instruction
  granularity.
- Spin versus compute, and instruction mix on IBS OP captures.
- Whole-machine profiles when the target is not known in advance, or a process cannot be
  attached; attach PIDs when the question is about one program.
- Correlating a workload's own clock with the capture, so a phase can be queried by
  capture-relative time.
- Captures that are kept and queried later: a session is a DuckDB database, not a bespoke
  report.

## Requirements

- AMD uProf CLI (`AMDuProfCLI`) 5.3 or later.
- DuckDB 2.x Python package.
- LLVM 23 or later: llvm-symbolizer; on Windows, llvm-pdbutil and llvm-readobj enable shared-address labelling.
- llvm-objdump for instruction context.

`tools/uprof.py tools` prints every resolved path and version against its minimum, and fails when
a required tool is missing or a found one is below its minimum. Windows is the verified host;
the Linux branch is kept but unverified on the reference host.

## Install

    claude plugin marketplace add Ext3h/amd-uprof-plugin
    claude plugin install amd-uprof@amd-uprof-dev

## Commands

The skill runs `tools/uprof.py`:

| Command | Use |
|---|---|
| `collect` | capture cycle or IBS OP samples, system-wide or attached |
| `translate` | symbolize a capture on a copy; optionally write the IBS ASCII dump |
| `profile` | samples and time shares by process, function, line or instruction |
| `anchor` | map a QPC reading to capture-relative seconds |
| `schema` | print the live DuckDB schema for drift checks |
| `tools` | print resolved tool paths and versions |

`SKILL.md` in `plugin/skills/amd-uprof/` is the entry point and the full contract; `references/`
carries the derivation notes and validation records.

## Layout

- `plugin/` — the plugin source: `.claude-plugin/plugin.json` and `skills/amd-uprof/` (the
  skill, its tools and references).
- `tests/` — maintainer-only test suite and fixtures; run with `python tests/run_tests.py`.
- `bench/` — maintainer-only timing harness (added by #40).
- `.claude-plugin/` — marketplace entry and the icon (`icon.svg` master, `icon.png` raster).

Validate a change with `claude plugin validate ./plugin`.

Drives the AMD uProf CLI; not affiliated with or endorsed by Advanced Micro Devices.
The icon's micro sign is set in Open Sans (Apache-2.0), the typeface uProf ships.
