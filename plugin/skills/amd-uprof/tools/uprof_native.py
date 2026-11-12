"""uProf tool discovery and translation.

Install paths are probed per OS with `shutil.which` plus a few conventional directories; nothing
is installed here. The Linux branches are kept but unverified on this host.
"""

from __future__ import annotations

import csv
import ctypes
import functools
import os
import re
import shutil
import statistics
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

from uprof_session import (ContextCadence, achieved_summary, derive_sampler, read_meta,
                           run_gap_limit_ns, system_wide)
from uprof_util import (COPY_DIRS, DUMP_FILENAMES, UprofError, absolute, contains,
                        copy_session, parse_time_filter, skill_identity, tail_lines)

IS_WINDOWS = os.name == "nt"
TRANSLATE_TIMEOUT: Final = 4 * 60 * 60
TRANSLATE_OUTPUTS: Final = ("cpu.db", "callstack.db", *DUMP_FILENAMES.values())
# Oldest releases the tools work with: uProf 5.3 writes cpu.db as DuckDB by default (older
# releases write SQLite), and LLVM 23 added llvm-symbolizer --pdb and llvm-objdump
# --no-symbolize-operands. A tool below its minimum stops the command that needs it.
UPROF_MINIMUM: Final = (5, 3)
LLVM_MINIMUM: Final = (23,)
LLVM_TOOLS: Final = ("llvm-symbolizer", "llvm-readobj", "llvm-pdbutil", "llvm-objdump")


# ---------------------------------------------------------------- tool discovery

def _first_existing(candidates: Iterable[str | os.PathLike[str] | None]) -> Path | None:
    for path in candidates:
        if path and Path(path).is_file():
            return absolute(path)
    return None


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _version_key(path: Path) -> tuple[int, ...]:
    """Numeric version from an install path, so llvm-19 sorts above llvm-9."""
    match = re.search(r"(?:llvm-|AMDuProf_|uProf_?)(\d+(?:\.\d+)*)", str(path))
    if not match:
        match = re.search(r"-(\d+(?:\.\d+)*)$", path.name)
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def _newest(paths: Iterable[Path]) -> list[Path]:
    return sorted(paths, key=_version_key, reverse=True)


def find_uprof() -> Path | None:
    env = os.environ.get("AMDUPROF_CLI")
    candidates: list[str | os.PathLike[str] | None] = [env, _which("AMDuProfCLI")]
    if IS_WINDOWS:
        for base in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles"),
                     os.environ.get("ProgramFiles(x86)")):
            if base:
                candidates.append(Path(base) / "AMD" / "AMDuProf" / "bin" / "AMDuProfCLI.exe")
    else:
        candidates.extend(_newest(Path("/opt").glob("AMDuProf_*/bin/AMDuProfCLI")))
        candidates.extend(_newest(Path("/opt").glob("AMD/uProf*/bin/AMDuProfCLI")))
        candidates.append(Path("/usr/local/bin/AMDuProfCLI"))
    return _first_existing(candidates)


def find_symbolizer() -> Path | None:
    env = os.environ.get("LLVM_SYMBOLIZER")
    candidates: list[str | os.PathLike[str] | None] = [env, _which("llvm-symbolizer")]
    if IS_WINDOWS:
        for base in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles")):
            if base:
                candidates.append(Path(base) / "LLVM" / "bin" / "llvm-symbolizer.exe")
    else:
        candidates.extend(_newest(Path("/usr/lib").glob("llvm-*/bin/llvm-symbolizer")))
        candidates.extend(_newest(Path("/usr/bin").glob("llvm-symbolizer-*")))
        candidates.append(Path("/usr/bin/llvm-symbolizer"))
    return _first_existing(candidates)


def find_sibling(symbolizer: Path | None, name: str) -> Path | None:
    """llvm-pdbutil, llvm-readobj and llvm-objdump usually sit next to llvm-symbolizer."""
    candidates: list[str | os.PathLike[str] | None] = [_which(name)]
    if symbolizer:
        candidates.insert(0, symbolizer.parent / (name + (".exe" if IS_WINDOWS else "")))
    return _first_existing(candidates)


def require_uprof() -> Path:
    found = find_uprof()
    if not found:
        hint = ("install AMD uProf, or set AMDUPROF_CLI to AMDuProfCLI.exe"
                if IS_WINDOWS else "install AMD uProf, or set AMDUPROF_CLI to the AMDuProfCLI binary")
        raise UprofError(f"AMDuProfCLI not found; {hint}")
    cause = uprof_version_cause(found, _uprof_version(found))
    if cause:
        raise UprofError(cause)
    return found


def require_symbolizer() -> Path:
    """The llvm-symbolizer; it and the found siblings symbolization uses must meet LLVM_MINIMUM."""
    found = find_symbolizer()
    if not found:
        hint = ("winget install --id LLVM.LLVM" if IS_WINDOWS
                else "install LLVM (for example: sudo apt install llvm)")
        raise UprofError(f"llvm-symbolizer not found; {hint} (or set LLVM_SYMBOLIZER)")
    require_llvm(SYMBOLIZE_TOOLS, found)
    return found


# llvm-readobj reads the PE GUID and llvm-pdbutil the fold cache, both only on Windows.
SYMBOLIZE_TOOLS: Final = (("llvm-symbolizer", "llvm-readobj", "llvm-pdbutil") if IS_WINDOWS
                          else ("llvm-symbolizer",))
# Instruction context symbolizes, reads imports with llvm-readobj and decodes with llvm-objdump.
CONTEXT_TOOLS: Final = ("llvm-symbolizer", "llvm-readobj", "llvm-objdump")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """The dotted version after the word "version", else a leading dotted number."""
    if not text:
        return None
    match = (re.search(r"(?i)\bversion\s+v?(\d+(?:\.\d+)*)", text)
             or re.match(r"\s*(\d+(?:\.\d+)+)", text))
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def _minimum_text(minimum: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in minimum)


def _version_cause(path: Path, version: str | None, minimum: tuple[int, ...], tool: str,
                   why: str, remedy: str) -> str | None:
    """None when version meets minimum, else one line with the cause and the alternatives."""
    found = parse_version(version)
    if found is not None and found >= minimum:
        return None
    floor = _minimum_text(minimum)
    if found is None:
        problem = f"cannot read the version of {path} (--version printed none)"
    else:
        problem = f"{path} is {tool} {_minimum_text(found)}, below the minimum {floor}"
    return f"{problem}; {tool} {floor} or later is required: {why}; remedy: {remedy}, then re-run"


def uprof_version_cause(path: Path, version: str | None) -> str | None:
    floor = _minimum_text(UPROF_MINIMUM)
    return _version_cause(
        path, version, UPROF_MINIMUM, "AMD uProf",
        "older releases do not write cpu.db as DuckDB by default, which the analysis reads",
        f"install AMD uProf {floor} or later from https://www.amd.com/en/developer/uprof.html, "
        f"or set AMDUPROF_CLI to an AMDuProfCLI of uProf {floor} or later")


def llvm_version_cause(path: Path, version: str | None) -> str | None:
    floor = _minimum_text(LLVM_MINIMUM)
    install = ("winget upgrade --id LLVM.LLVM" if IS_WINDOWS
               else f"install LLVM {floor} or later from apt.llvm.org")
    return _version_cause(
        path, version, LLVM_MINIMUM, "LLVM",
        "llvm-symbolizer --pdb and llvm-objdump --no-symbolize-operands need it",
        f"{install}, or set LLVM_SYMBOLIZER to an llvm-symbolizer of LLVM {floor} or later "
        "whose directory holds the other LLVM tools")


def _llvm_path(name: str, symbolizer: Path | None) -> Path | None:
    return symbolizer if name == "llvm-symbolizer" else find_sibling(symbolizer, name)


def require_llvm(names: Iterable[str], symbolizer: Path | None = None) -> None:
    """Stop when a found LLVM tool among names is below LLVM_MINIMUM; absent tools pass here,
    because each caller reports absence with its own cause."""
    symbolizer = symbolizer if symbolizer else find_symbolizer()
    for name in names:
        path = _llvm_path(name, symbolizer)
        if path:
            cause = llvm_version_cause(path, _first_version_line(path, "--version"))
            if cause:
                raise UprofError(cause)


class SymbolizerUnsupported(UprofError):
    """The installed llvm-symbolizer lacks an option the run needs; the message is the remedy."""


@functools.lru_cache(maxsize=None)
def pdb_option_cause(symbolizer: str) -> str | None:
    """None when this llvm-symbolizer accepts --pdb, else the cause and remedy in one line.

    llvm-symbolizer has an explicit --pdb option only from LLVM 23; an older one rejects it as an
    unknown argument, which fails every module that has an accepted PDB. A help text that cannot
    be read is not evidence of a missing option, so it does not block symbolization.
    """
    try:
        completed = run([symbolizer, "--help"], timeout=30)
    except (UprofError, OSError):
        return None
    text = (completed.stdout or "") + "\n" + (completed.stderr or "")
    if completed.returncode != 0 or not text.strip() or re.search(r"--pdb[=\s]", text):
        return None
    version = _first_version_line(Path(symbolizer), "--version") or "version unknown"
    hint = ("winget upgrade --id LLVM.LLVM" if IS_WINDOWS
            else "install LLVM 23 or later from apt.llvm.org")
    return (f"{symbolizer} ({version}) has no --pdb option, so it cannot read a PDB; "
            f"LLVM >= 23 required: {hint}, or set LLVM_SYMBOLIZER to an LLVM >= 23 "
            "llvm-symbolizer, then re-run")


def require_pdb_option(symbolizer: Path) -> None:
    cause = pdb_option_cause(str(symbolizer))
    if cause:
        raise SymbolizerUnsupported(cause)


def run(command: Sequence[str], timeout: int | None = None, input_text: str | None = None,
        ) -> subprocess.CompletedProcess[str]:
    """Run a native tool with UTF-8 text output and no console-window flash."""
    kwargs = {"capture_output": True, "text": True, "encoding": "utf-8",
              "errors": "replace", "timeout": timeout}
    if input_text is not None:
        kwargs["input"] = input_text
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        return subprocess.run(command, **kwargs)
    except FileNotFoundError as exc:
        raise UprofError(f"cannot run {command[0]}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise UprofError(f"{Path(command[0]).name} timed out after {timeout}s") from exc


def print_output(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(completed.stderr, end="" if completed.stderr.endswith("\n") else "\n", file=sys.stderr)


def failure_detail(completed: subprocess.CompletedProcess[str]) -> str:
    return tail_lines((completed.stdout or "") + "\n" + (completed.stderr or ""))


def symbol_cache_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "Symbols"
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "amd-uprof" / "symbols"


def default_symbol_servers() -> list[str]:
    return ["https://msdl.microsoft.com/download/symbols"] if IS_WINDOWS else []


def parse_symbol_path(value: str | None) -> tuple[str | None, list[str]]:
    """Return (download cache, symbol servers) from a Windows-style _NT_SYMBOL_PATH."""
    cache = None
    servers: list[str] = []
    if not value:
        return cache, servers
    for entry in value.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("*")
        if len(parts) >= 3 and parts[0].lower() == "srv":
            if not cache and parts[1]:
                cache = parts[1]
            servers.append(entry)
    return cache, servers


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ibs_unavailable_reason() -> str:
    """Explain why IBS counters are missing, naming VBS or a hypervisor when that is the cause."""
    if IS_WINDOWS:
        try:
            systeminfo = run(["systeminfo"], timeout=60).stdout
        except UprofError:
            systeminfo = ""
        lowered = systeminfo.lower()
        vbs_line = next((line for line in lowered.splitlines()
                         if "virtualization-based security" in line), "")
        disabled = "not running" in vbs_line or "not enabled" in vbs_line
        vbs = not disabled and ("running" in vbs_line or "enabled" in vbs_line)
        hypervisor = "hypervisor has been detected" in lowered
        if vbs or hypervisor:
            state = "VBS running" if vbs else "hypervisor detected"
            return (f"hypervisor/VBS is active ({state}; check Win32_DeviceGuard: "
                    "VirtualizationBasedSecurityStatus is 2 when running)")
        return ("no IBS counters are available; check that Hyper-V/VBS is disabled and "
                "Win32_DeviceGuard reports VirtualizationBasedSecurityStatus 0")
    try:
        with open(Path("/proc/cpuinfo"), "r", encoding="utf-8", errors="replace") as handle:
            if " hypervisor" in handle.read():
                return "a hypervisor is active (/proc/cpuinfo reports the hypervisor flag)"
    except OSError:
        pass
    if any(Path("/sys/module").glob("kvm*")):
        return "the KVM kernel module is loaded; IBS counters are not exposed to this host"
    return "no IBS counters are available; check the kernel, virtualization and perf permissions"


def _first_version_line(path: Path, *args: str) -> str | None:
    """The first line of `<tool> --version` that names a version, else its first line."""
    try:
        completed = run([str(path), *args], timeout=30)
    except (UprofError, OSError):
        return None
    if completed.returncode != 0:
        return None
    lines = [line.strip() for line
             in ((completed.stdout or "") + "\n" + (completed.stderr or "")).splitlines()
             if line.strip()]
    if not lines:
        return None
    return next((line for line in lines if "version" in line.lower()), lines[0])


def _tool_row(name: str, path: Path | None, version: str | None,
              missing: str = "not found", minimum: tuple[int, ...] | None = None,
              too_old: str | None = None) -> str:
    """One `tools` row; missing is the cause (and remedy) printed when path is absent, and
    too_old the cause when the found version is below minimum."""
    if not path:
        return f"{name}=; version=MISSING ({missing})"
    row = f"{name}={path}; version={version or 'unavailable'}"
    if minimum is not None:
        status = "TOO OLD" if parse_version(version) else "UNREADABLE"
        row += f"; minimum={_minimum_text(minimum)}; " + (f"{status}: {too_old}" if too_old else "ok")
    return row


def _uprof_version(path: Path | None) -> str | None:
    if path is None:
        return None
    version = _first_version_line(path, "--version")
    if version:
        return version
    path_version = ".".join(str(part) for part in _version_key(path))
    if path_version:
        return f"{path_version} (from the install path; --version gave nothing)"
    return "unavailable (--version failed and the install path carries no version)"


def tool_report() -> None:
    """Print every tool path and version against its minimum, then fail once if a required tool
    is missing or a found tool is below its minimum."""
    uprof = find_uprof()
    symbolizer = find_symbolizer()
    pdbutil = find_sibling(symbolizer, "llvm-pdbutil")
    readobj = find_sibling(symbolizer, "llvm-readobj")
    objdump = find_sibling(symbolizer, "llvm-objdump")
    try:
        import duckdb
        version = duckdb.__version__
        try:
            major = int(version.split(".")[0])
        except (AttributeError, ValueError):
            major = 0
        if major < 2:
            duckdb_version = None
            duckdb_short = None
            duckdb_hint = (f"DuckDB {version} is too old (need 2.x); upgrade with: "
                           f"{sys.executable} -m pip install --upgrade duckdb")
        else:
            duckdb_version = f"duckdb {version} (python)"
            duckdb_short = version
            duckdb_hint = None
    except ImportError:
        duckdb_version = None
        duckdb_short = None
        duckdb_hint = f"DuckDB Python module (install with: {sys.executable} -m pip install duckdb)"
    too_old: list[str] = []

    def row(name: str, path: Path | None, version: str | None, minimum: tuple[int, ...],
            cause_of, tool: str, missing: str = "not found") -> str:
        cause = cause_of(path, version) if path else None
        if cause:
            too_old.append(tool)
        return _tool_row(name, path, version, missing, minimum, cause)

    def llvm_row(name: str, path: Path | None, tool: str, missing: str = "not found") -> str:
        version = _first_version_line(path, "--version") if path else None
        return row(name, path, version, LLVM_MINIMUM, llvm_version_cause, tool, missing)

    print(row("UPROF", uprof, _uprof_version(uprof), UPROF_MINIMUM, uprof_version_cause,
              "AMDuProfCLI"))
    print(f"DUCKDB={duckdb_version or ''}; version={duckdb_short or 'MISSING (not installed)'}")
    print(llvm_row("SYMBOLIZER", symbolizer, "llvm-symbolizer"))
    print(llvm_row("PDBUTIL", pdbutil, "llvm-pdbutil"))
    print(llvm_row("READOBJ", readobj, "llvm-readobj"))
    print(llvm_row("OBJDUMP", objdump, "llvm-objdump",
                   "llvm-objdump is not beside llvm-symbolizer or on PATH; instruction context "
                   "is omitted; remedy: install LLVM or add its bin directory to PATH; "
                   "module/RVA rows still work"))
    failures = []
    if too_old:
        failures.append("TOO OLD or UNREADABLE " + ", ".join(too_old)
                        + " (each row names the remedy)")
    missing = []
    if not uprof:
        missing.append("uProf CLI (install AMD uProf or set AMDUPROF_CLI)")
    if not duckdb_version:
        missing.append(duckdb_hint)
    if not symbolizer:
        missing.append("llvm-symbolizer (install LLVM or set LLVM_SYMBOLIZER)")
    if missing:
        failures.insert(0, "MISSING " + "; ".join(missing))
    if failures:
        raise UprofError("; ".join(failures))


# ---------------------------------------------------------------- translate

def translate_command(uprof: str | Path, session: str | Path, *,
                      symbol_cache: str | Path | None = None,
                      symbol_servers: Iterable[str] = (),
                      symbol_paths: Iterable[str | Path] = (),
                      time_filter: str | None = None,
                      ascii_kind: str | None = None) -> list[str]:
    """The AMDuProfCLI translate argument list shared by translate and the dump cache."""
    command = [os.fspath(uprof), "translate", "-i", os.fspath(session)]
    if symbol_cache is not None:
        command += ["--symbol-cache-dir", os.fspath(symbol_cache)]
    for server in symbol_servers:
        command += ["--symbol-server", server]
    for path in symbol_paths:
        command += ["--symbol-path", os.fspath(path)]
    if time_filter:
        command += ["--time-filter", time_filter]
    if ascii_kind:
        command += ["--ascii", ascii_kind]
    return command


def dump_cadence(path: Path, context_key: str | tuple[str, ...] = "CPU_Number",
                 gap_limit_ns: float | None = None
                 ) -> tuple[int, int, list[ContextCadence]]:
    """Sample rows, distinct CPU_Number values and per-context cadence in an ASCII dump.

    context_key is CPU_Number for a system-wide capture and (PID, TID) for an attached one, so
    same-TID threads of different processes stay separate; if any named column is missing the
    context falls back to CPU_Number. Per-context DeltaTicks are held to take an exact median, so
    memory grows with the dump. gap_limit_ns drops gaps above it, which are time the context was
    not sampling continuously; None keeps every gap.
    """
    samples = 0
    cpus: set[str] = set()
    ticks: dict[tuple[str, ...], list[int]] = {}
    keys = (context_key,) if isinstance(context_key, str) else context_key
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header is None:
            return 0, 0, []
        try:
            cpu_index = header.index("CPU_Number")
            delta_index = header.index("DeltaTick")
        except ValueError:
            return 0, 0, []
        key_indices = ([header.index(key) for key in keys]
                       if all(key in header for key in keys) else [cpu_index])
        for row in reader:
            if not row:
                continue
            samples += 1
            if len(row) > cpu_index:
                cpus.add(row[cpu_index])
            try:
                tick = int(row[delta_index])
            except (IndexError, ValueError):
                continue
            key = tuple(row[index] if len(row) > index else "?" for index in key_indices)
            ticks.setdefault(key, []).append(tick)
    contexts: list[ContextCadence] = []
    for values in ticks.values():
        values.sort()
        gaps = [later - earlier for earlier, later in zip(values, values[1:])]
        if gap_limit_ns is not None:
            gaps = [gap for gap in gaps if gap <= gap_limit_ns]
        contexts.append(ContextCadence(
            samples=len(values),
            median_gap_ns=statistics.median(gaps) if gaps else None))
    return samples, len(cpus), contexts


def _dump_window_s(session: Path, time_filter: str | None) -> float | None:
    """The dump's window: the translate window when given, else the recorded capture elapsed."""
    if time_filter:
        bounds = parse_time_filter(time_filter)
        if bounds is not None:
            return float(bounds[1] - bounds[0])
    meta = read_meta(session) or {}
    elapsed_ms = ((meta.get("collection") or {}).get("schedule") or {}).get("elapsed")
    try:
        return int(elapsed_ms) / 1000.0
    except (TypeError, ValueError):
        return None


def _shown(path: Path) -> str:
    """path, followed by where it resolves when that differs from how it was given."""
    try:
        resolved = os.path.realpath(path)
    except (OSError, ValueError):
        return os.fspath(path)
    if os.path.normcase(resolved) == os.path.normcase(os.fspath(path)):
        return os.fspath(path)
    return f"{path} (resolves to {resolved})"


def _refuse_overlap(out: Path, session: Path) -> None:
    """Refuse an out-dir that is the session or nests with it, however either is spelled.

    Run it again directly before anything in out is removed or copied, so a path swapped for a
    link after the first check is still caught.
    """
    if contains(out, session) or contains(session, out):
        raise UprofError(f"--out-dir {_shown(out)} overlaps --session {_shown(session)} (the "
                         "same directory under another name, or one inside the other): "
                         "translate rewrites cpu.db, callstack.db and session.uprof, so it works "
                         "on a copy. Choose an --out-dir outside the session")


def _clear_translate_outputs(out: Path) -> None:
    """Remove what an earlier translate copied and generated in out.

    The copied raw session directories are inputs to the next translation, so stale ones from a
    different session would be translated alongside the new copy.
    """
    for name in (*COPY_DIRS, "session.uprof", *TRANSLATE_OUTPUTS):
        path = out / name
        try:
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
        except OSError as exc:
            raise UprofError(f"cannot remove {path} for --force: {exc}; choose another "
                             "--out-dir or fix its permissions") from exc


def symbolization_counts(cpu_db: Path | str) -> tuple[int, int | None, int] | None:
    """Modules, modules recording debug info and Function rows in a translated cpu.db.

    AMDuProfCLI translate exits 0 and prints a generic "Translation finished" even when no
    module got symbols, so these counts are the only evidence that translation resolved any.
    Returns None when the database cannot be inspected; the caller reports that, not success.
    """
    try:
        import duckdb
    except ImportError:
        return None
    try:
        connection = duckdb.connect(str(cpu_db), read_only=True)
    except Exception:
        return None
    try:
        columns = {str(name).lower() for name, in connection.execute(
            "SELECT lower(column_name) FROM duckdb_columns() "
            "WHERE lower(table_name) = 'module'").fetchall()}
        modules = connection.execute("SELECT count(*) FROM Module").fetchone()[0]
        with_debug = (connection.execute(
            "SELECT count(*) FROM Module WHERE foundDebugInfo").fetchone()[0]
            if "founddebuginfo" in columns else None)
        functions = connection.execute("SELECT count(*) FROM Function").fetchone()[0]
        return int(modules), (None if with_debug is None else int(with_debug)), int(functions)
    except Exception:
        return None
    finally:
        connection.close()


def translate(session_dir: Path | str, out_dir: Path | str,
              symbol_paths: Iterable[str | Path] | None = None,
              symbol_cache: Path | str | None = None,
              symbol_servers: list[str] | None = None, time_filter: str | None = None,
              ascii_kind: str | None = None, force: bool = False) -> None:
    session = absolute(session_dir)
    if not session.is_dir():
        raise UprofError(f"session directory not found: {session}")
    if not (session / "session.uprof").is_file():
        raise UprofError(f"session.uprof not found in {session}")
    out = absolute(out_dir)
    if out.exists() and not out.is_dir():
        raise UprofError(f"output path exists and is not a directory: {out}; choose another "
                         "--out-dir")
    _refuse_overlap(out, session)
    # Copied inputs count too: a translate that stopped after the copy leaves them, and copying
    # another capture over them would merge both captures' raw files into one translation.
    conflicts = [out / name for name in (*TRANSLATE_OUTPUTS, "session.uprof", *COPY_DIRS)
                 if os.path.lexists(out / name)]
    if conflicts and not force:
        shown = ", ".join(os.fspath(path) for path in conflicts)
        raise UprofError(
            f"--out-dir already holds a previous translation or its copied inputs ({shown}); "
            "translate never appends to it or merges into it. Choose another --out-dir, or pass "
            "--force to replace the files translate copied and generated there")
    if time_filter and parse_time_filter(time_filter) is None:
        raise UprofError("--time-filter needs T1:T2 in seconds from capture start, e.g. 0:5")
    if ascii_kind and ascii_kind not in DUMP_FILENAMES:
        raise UprofError(f"unknown --ascii kind {ascii_kind!r}; use ibsop-event-dump or "
                         "ibsfetch-event-dump")

    env_cache, env_servers = parse_symbol_path(os.environ.get("_NT_SYMBOL_PATH"))
    cache = symbol_cache or env_cache or symbol_cache_dir()
    servers = list(dict.fromkeys([*(env_servers or default_symbol_servers()),
                                  *(symbol_servers or [])]))
    print(f"VERSION={skill_identity()}")
    print(f"SYMBOL_CACHE={cache}")
    print(f"SYMBOL_SERVERS={' | '.join(servers)}")

    uprof = require_uprof()
    _refuse_overlap(out, session)
    if force:
        _clear_translate_outputs(out)
    copy_session(session, out)

    command = translate_command(
        uprof, out, symbol_cache=cache, symbol_servers=servers,
        symbol_paths=[absolute(path) for path in symbol_paths or ()],
        time_filter=time_filter, ascii_kind=ascii_kind)

    completed = run(command, timeout=TRANSLATE_TIMEOUT)
    print_output(completed)
    if completed.returncode != 0:
        raise UprofError(f"translate failed with {completed.returncode}: "
                         f"{failure_detail(completed)}")

    cpu_db = out / "cpu.db"
    if not cpu_db.is_file():
        raise UprofError(f"translate did not produce {cpu_db}")
    print(f"SESSION={out}")
    print(f"CPU_DB={cpu_db}")
    counts = symbolization_counts(cpu_db)
    if counts is None:
        print("SYMBOLIZATION: could not inspect cpu.db; check Module.foundDebugInfo and Function "
              "rows before relying on names")
    else:
        modules, with_debug, functions = counts
        debug_text = ("Module.foundDebugInfo absent" if with_debug is None
                      else f"{with_debug}/{modules}")
        print(f"SYMBOLIZATION: {debug_text} modules with debug info, {functions} Function rows")
        if functions == 0 or with_debug == 0:
            print("WARNING: translate exited 0 and printed 'Translation finished', but this "
                  "cpu.db has no symbol evidence; the exit status is not symbolization success. "
                  "Check the SYMBOL_CACHE and SYMBOL_SERVERS paths above, or pass --symbol-cache, "
                  "--symbol-server or --symbol-path and re-run translate into a new --out-dir")
    if ascii_kind:
        dump = out / DUMP_FILENAMES[ascii_kind]
        if not dump.is_file():
            raise UprofError(f"translate --ascii {ascii_kind} did not produce "
                             f"{DUMP_FILENAMES[ascii_kind]} in {out}")
        print(f"ASCII_DUMP={dump}")
        sampler = derive_sampler(out)
        wide = system_wide(out)
        label = "CPU" if wide else "thread"
        samples, cpus, contexts = dump_cadence(
            dump, "CPU_Number" if wide else ("PID", "TID"), run_gap_limit_ns(sampler))
        window_s = _dump_window_s(out, time_filter)
        print(f"ACHIEVED: {achieved_summary(samples, window_s, cpus, sampler, contexts, label)}")
    else:
        print("ACHIEVED: reported at profile time (translate wrote no dump without --ascii)")
