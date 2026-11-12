# Timer-capture fixture

A real timer-based capture (`AMDuProfCLI collect --config tbp`) of `heap_churn.exe`, used by
`test_timer_capture.py`. The committed `heap_churn.exe` and `heap_churn.pdb` are the fixture; the
source and the commands below are its provenance. Nothing here is third-party code; the files are
distributed under the repository's license.

## Files

| File | Role |
|---|---|
| `heap_churn.c`, `kernel32.def` | source: a byte hash (`hash_block`, `fill_block`) plus one `HeapAlloc`/`HeapFree` per block |
| `heap_churn.exe`, `heap_churn.pdb` | the image and its PDB, built without host paths |
| `session.uprof` | the capture's `session.uprof`, reduced to the keys the tools read, host values replaced |
| `cpu_tables.json` | the translated `cpu.db` tables `profile` reads, image paths replaced by `c:\fixture\heap_churn.exe` |
| `export_fixture.py` | writes `session.uprof` and `cpu_tables.json` from a translated session |

`tests/timer_fixture.py` rebuilds `cpu.db` from `cpu_tables.json`; no DuckDB file is committed
because its storage format is bound to the DuckDB version.

## Properties the tests rely on

- 1445 `UnifiedSampleSeries` rows carrying 1446 samples, all on one thread: `heap_churn.exe`
  1052 (`hash_block` 826), `ntdll.dll` 393, `apphelp.dll` 1.
- `timerInterval` 1 ms; one `CPU_TIME` event column `event#0x200000000e000` (`hwEventId` 57344).
- Every `heap_churn.exe` sample address lies in a `Function` range uProf resolved from the PDB.

## Recreating

Built with LLVM 22.1.6 and captured with AMDuProfCLI 5.3.521 on Windows 11 (Intel CPU, so only
timer sampling is available). Run from this directory:

```console
clang --target=x86_64-pc-windows-msvc -O2 -g -gcodeview -fdebug-compilation-dir=. -fcoverage-compilation-dir=. -nostdinc -ffreestanding -fno-builtin -fno-stack-protector -c heap_churn.c -o heap_churn.obj
llvm-dlltool -m i386:x86-64 -d kernel32.def -l kernel32.lib
lld-link /nodefaultlib /subsystem:console /entry:heap_churn_entry /debug /pdbaltpath:%_PDB% /pdbsourcepath:. /release /out:heap_churn.exe heap_churn.obj kernel32.lib
AMDuProfCLI collect --config tbp -o <NEW_OUT_DIR> ./heap_churn.exe
python ../../../plugin/skills/amd-uprof/tools/uprof.py translate --session <NEW_OUT_DIR> --out-dir <NEW_TR_DIR>
python export_fixture.py <NEW_TR_DIR>
```

`heap_churn.obj` and `kernel32.lib` are build intermediates and are not committed. A recapture
changes the sample counts; update the counts above and in `test_timer_capture.py`.
