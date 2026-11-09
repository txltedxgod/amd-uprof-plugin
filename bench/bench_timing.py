"""Time the AMD uProf skill's commands and attribute each stage.

Two modes per case:

* plain: no patches, no cProfile. The wall time the user feels, and the number the
  performance budget is set from.
* instrumented: DuckDB's own JSON profiler and a subprocess probe, plus cProfile over
  the Python frames. Used for the stage table, not for the budget.

Requires the `duckdb` package (the skill already does). No other dependency.
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import io
import json
import os
import pstats
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = 1
PROFILE_CASES = (
    "profile-process",
    "profile-module",
    "profile-function",
    "profile-line",
    "profile-region",
    "profile-instruction",
)
CASE_BY_SCOPE = {
    "profile-process": "process",
    "profile-module": "module",
    "profile-function": "function",
    "profile-line": "line",
    "profile-region": "region",
    "profile-instruction": "instruction",
}
DEFAULT_CASES = "profile-process,profile-module,profile-function,profile-line"
TRANSLATE_CASES = ("translate", "translate-ascii")
ALL_CASES = PROFILE_CASES + TRANSLATE_CASES + ("collect",)
PROCESS_SCAN_FUNCTIONS = ("READ_CSV", "READ_CSV_AUTO")

# (function name, required file substring or None, stage label). Duplicate Python names are
# narrowed by the file substring; "run" would otherwise match unrelated helpers.
STAGE_FUNCTIONS: tuple[tuple[str, str | None, str], ...] = (
    ("run_query_command", "uprof_query.py", "python: query command"),
    ("run_script", "uprof_db.py", "duckdb: views.sql load"),
    ("fetch_typed", "uprof_db.py", "duckdb: fetch"),
    ("_dump_sanity", "uprof_query.py", "duckdb: v_dump_sanity"),
    ("_capture_scan", "uprof_query.py", "duckdb: capture scan"),
    ("_dump_contexts", "uprof_query.py", "duckdb: dump contexts"),
    ("_achieved_field", "uprof_query.py", "duckdb: achieved"),
    ("_scope_warning", "uprof_query.py", "duckdb: scope warning"),
    ("_coverage_values", "uprof_query.py", "duckdb: kernel coverage"),
    ("_agreement_values", "uprof_query.py", "duckdb: agreement"),
    ("_hot_rva_field", "uprof_query.py", "duckdb: hot rva"),
    ("_write_profile", "uprof_query.py", "duckdb: final projection + render"),
    ("symbolize_modules", "uprof_symbols.py", "llvm: symbolization"),
    ("symbolize_module", "uprof_symbols.py", "llvm: symbolization (per module)"),
    ("probe_paths", "uprof_symbols.py", "llvm: symbol/image path probe"),
    ("symbolizer_search_paths", "uprof_symbols.py", "llvm: symbol path search"),
    ("resolve_image", "uprof_symbols.py", "llvm: image resolution"),
    ("_candidate_pdbs", "uprof_symbols.py", "llvm: PDB candidates"),
    ("_choose_pdb", "uprof_symbols.py", "llvm: PDB choice"),
    ("_probe_pdb", "uprof_symbols.py", "llvm: PDB probe"),
    ("_run_symbolizer", "uprof_symbols.py", "llvm: llvm-symbolizer"),
    ("public_symbols", "uprof_symbols.py", "llvm: llvm-pdbutil publics"),
    ("_derive_scope_ranges", "uprof_query.py", "llvm: function ranges"),
    ("derive_module_ranges", "uprof_functions.py", "llvm: function ranges (per module)"),
    ("copy_session", "uprof_util.py", "io: session copy"),
    ("resolve_dump", "uprof_dump.py", "dump: resolve"),
    ("_make_dump", "uprof_dump.py", "dump: generate ASCII"),
    ("translate", "uprof_native.py", "python: translate"),
    ("collect", "uprof_collect.py", "python: collect"),
    ("run", "subprocess.py", "subprocess: all children"),
    ("read_meta", "uprof_session.py", "python: session.uprof read"),
    ("derive_sampler", "uprof_session.py", "python: session.uprof read"),
    ("recorded_time_filter", "uprof_dump.py", "python: session.uprof read"),
    ("output_rows", "uprof_db.py", "render: output"),
)


# ---------------------------------------------------------------- small helpers

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(chunk), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _row_count(path: Path) -> int | None:
    """Data rows: LF count minus the header. The dump is UTF-8 with LF or CRLF."""
    try:
        with open(path, "rb") as handle:
            lines = 0
            while block := handle.read(1 << 20):
                lines += block.count(b"\n")
    except OSError:
        return None
    return max(lines - 1, 0)


def _p95(sorted_values: list[float]) -> float:
    """Nearest-rank p95, so the number is always one of the measured values."""
    if not sorted_values:
        return 0.0
    index = max(0, min(len(sorted_values) - 1, int(0.95 * len(sorted_values) + 0.999999) - 1))
    return sorted_values[index]


def _summarize(values: Iterable[float | None]) -> dict[str, Any]:
    present = [value for value in values if value is not None]
    if not present:
        return {"count": 0}
    ordered = sorted(present)
    return {
        "count": len(present),
        "values_s": present,
        "min_s": ordered[0],
        "median_s": statistics.median(ordered),
        "mean_s": statistics.fmean(ordered),
        "p95_s": _p95(ordered),
        "max_s": ordered[-1],
        "stdev_s": statistics.stdev(ordered) if len(ordered) > 1 else 0.0,
    }


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cpu_times() -> tuple[int, int, int] | None:
    """Idle, kernel and user 100 ns counters for the whole machine (Windows)."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class FileTime(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        def ticks(value: "FileTime") -> int:
            return (value.high << 32) | value.low

        idle, kernel, user = FileTime(), FileTime(), FileTime()
        if not ctypes.windll.kernel32.GetSystemTimes(
                ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return ticks(idle), ticks(kernel), ticks(user)
    except (AttributeError, OSError, ValueError):
        return None


def _system_cpu_percent(before: tuple[int, int, int] | None,
                        after: tuple[int, int, int] | None) -> float | None:
    """Busy share of all processors during the rep; kernel time includes idle time."""
    if before is None or after is None:
        return None
    idle = after[0] - before[0]
    total = (after[1] - before[1]) + (after[2] - before[2])
    if total <= 0:
        return None
    return max(0.0, min(100.0, (1.0 - idle / total) * 100.0))


def _command_label(command: Iterable[str]) -> str:
    parts = [str(part) for part in command]
    if not parts:
        return "?"
    name = Path(parts[0]).name
    markers: list[str] = []
    for part in parts[1:]:
        if part in ("translate", "collect", "report", "--ascii", "ibsop-event-dump",
                    "--version", "-version"):
            markers.append(part)
        elif part in ("--coff-unwind", "--coff-exports", "--coff-imports", "--unwind",
                      "--exports", "--publics", "--summary", "dump"):
            markers.append(part)
        if len(markers) >= 2:
            break
    return name + (":" + ",".join(markers) if markers else "")


def _run_version(command: list[str] | None) -> str | None:
    if not command:
        return None
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=15, creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (done.stdout or done.stderr or "").strip().splitlines()
    return text[0] if text else None


def _git(repo: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _host_snapshot() -> dict[str, Any]:
    memory_bytes = None
    try:
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("memory_load", ctypes.c_ulong),
                        ("total_phys", ctypes.c_ulonglong), ("avail_phys", ctypes.c_ulonglong),
                        ("total_page", ctypes.c_ulonglong), ("avail_page", ctypes.c_ulonglong),
                        ("total_virtual", ctypes.c_ulonglong),
                        ("avail_virtual", ctypes.c_ulonglong),
                        ("avail_extended", ctypes.c_ulonglong)]

        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            memory_bytes = status.total_phys
    except (AttributeError, OSError, ValueError):
        pass
    load = None
    if os.name == "nt":
        load_text = _run_version([
            "powershell", "-NoProfile", "-Command",
            "((Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples[0].CookedValue)"
            ".ToString([System.Globalization.CultureInfo]::InvariantCulture)"])
        try:
            load = float(load_text.replace(",", ".")) if load_text else None
        except ValueError:
            load = None
    return {
        "platform": sys.platform,
        "machine": os.environ.get("PROCESSOR_IDENTIFIER"),
        "logical_cpus": os.cpu_count(),
        "total_ram_bytes": memory_bytes,
        "cpu_load_percent_at_start": load,
    }


def _session_identity(session: Path) -> dict[str, Any]:
    cpu_db = session / "cpu.db"
    uprof_meta = session / "session.uprof"
    dump = session / "IbsOpDump.csv"
    if not dump.is_file():
        # Same key the tool uses (uprof_dump.cache_dir), but never generate a dump here.
        digest = hashlib.sha256(os.path.normcase(os.path.abspath(session))
                                .encode("utf-8")).hexdigest()[:16]
        cache_dump = Path(tempfile.gettempdir()) / "uprof-dump-cache" / digest / "IbsOpDump.csv"
        if cache_dump.is_file():
            dump = cache_dump
    found_dump = dump if dump.is_file() else None
    return {
        "session": str(session),
        "cpu_db_bytes": cpu_db.stat().st_size if cpu_db.is_file() else None,
        "cpu_db_sha256": _sha256_file(cpu_db) if cpu_db.is_file() else None,
        "session_uprof_bytes": uprof_meta.stat().st_size if uprof_meta.is_file() else None,
        "session_uprof_sha256": _sha256_file(uprof_meta) if uprof_meta.is_file() else None,
        "dump": str(found_dump) if found_dump else None,
        "dump_bytes": found_dump.stat().st_size if found_dump else None,
        "dump_rows": _row_count(found_dump) if found_dump else None,
        "dump_sha256": _sha256_file(found_dump) if found_dump else None,
        "dump_beside_session": bool(found_dump and found_dump.parent == session),
    }


# ---------------------------------------------------------------- output capture

class _Sink(io.TextIOBase):
    """stdout/stderr replacement that keeps both text and the `.buffer` byte path."""

    def __init__(self) -> None:
        super().__init__()
        self._bytes = io.BytesIO()
        self._text = io.TextIOWrapper(self._bytes, encoding="utf-8", errors="replace",
                                      newline="", write_through=True)

    @property
    def buffer(self) -> io.BytesIO:
        return self._bytes

    def write(self, text: str) -> int:
        return self._text.write(text)

    def flush(self) -> None:
        self._text.flush()

    def reconfigure(self, **kwargs: Any) -> None:
        try:
            self._text.reconfigure(**kwargs)
        except (AttributeError, ValueError):
            pass

    def bytes_value(self) -> bytes:
        self._text.flush()
        return self._bytes.getvalue()


# ---------------------------------------------------------------- DuckDB proxy

def _duckdb_module() -> Any:
    import duckdb
    return duckdb


def _sql_literal(path: Path) -> str:
    return "'" + path.as_posix().replace("'", "''") + "'"


def _walk_operators(nodes: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for node in nodes or ():
        yield node
        yield from _walk_operators(node.get("children", ()))


class Recorder:
    """Per-run statement and subprocess records, shared by every proxied connection."""

    def __init__(self, work_dir: Path, keep_profiles: bool = False) -> None:
        self.profile_dir = work_dir / "duckprof"
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.keep_profiles = keep_profiles
        self.statements: list[dict[str, Any]] = []
        self.subprocesses: list[dict[str, Any]] = []
        self._sequence = 0
        self._read_paths: set[Path] = set()

    def next_profile_path(self) -> Path:
        self._sequence += 1
        return self.profile_dir / f"q{self._sequence:05d}.json"

    def read_profile(self, path: Path | None) -> dict[str, Any] | None:
        if path is None or path in self._read_paths:
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None  # CREATE VIEW and plain CREATE have no profile
        except (OSError, ValueError):
            return None
        self._read_paths.add(path)
        if not self.keep_profiles:
            try:
                path.unlink()
            except OSError:
                pass
        try:
            document = json.loads(text)
        except ValueError:
            return None
        if not isinstance(document, dict) or not isinstance(document.get("query"), dict):
            return None
        return document

    def record_statement(self, record: dict[str, Any]) -> None:
        record["seq"] = len(self.statements)
        self.statements.append(record)


def _profile_summary(document: dict[str, Any]) -> dict[str, Any]:
    query = document.get("query", {})
    io = document.get("io", {})
    scans = []
    for node in _walk_operators(document.get("operator", ())):
        extra = node.get("extra_info") or {}
        function = extra.get("Function", "")
        if node.get("type") == "TABLE_SCAN" and str(function).startswith(PROCESS_SCAN_FUNCTIONS):
            scans.append({
                "function": function,
                "timing_s": node.get("timing"),
                "rows_scanned": node.get("rows_scanned"),
                "intermediate_rows": node.get("intermediate_rows"),
                "files": extra.get("Filename(s)"),
            })
    return {
        "query_total_s": query.get("total_time"),
        "query_cpu_s": query.get("cpu_time"),
        "planner_s": (document.get("planner") or {}).get("total_time"),
        "optimizer_s": (document.get("optimizer") or {}).get("total_time"),
        "bytes_read": io.get("total_bytes_read"),
        "bytes_written": io.get("total_bytes_written"),
        "rows_scanned": query.get("total_rows_scanned"),
        "csv_scans": scans,
    }


class RelationProxy:
    def __init__(self, relation: Any, connection: "ConnectionProxy", path: Path | None,
                 sql: str, statement_type: str) -> None:
        object.__setattr__(self, "_relation", relation)
        object.__setattr__(self, "_connection", connection)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_sql", sql)
        object.__setattr__(self, "_statement_type", statement_type)
        object.__setattr__(self, "_finished", False)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._relation, name)

    def _finish(self, fetch_wall: float) -> None:
        if self._finished:
            return
        object.__setattr__(self, "_finished", True)
        self._connection._record(self._sql, self._statement_type, "sql", 0.0, fetch_wall,
                                 self._path)

    def fetchall(self) -> list[Any]:
        started = time.perf_counter()
        try:
            rows = self._relation.fetchall()
        finally:
            wall = time.perf_counter() - started
        self._finish(wall)
        return rows

    def fetchone(self) -> Any:
        started = time.perf_counter()
        row = self._relation.fetchone()
        wall = time.perf_counter() - started
        if row is None:
            self._finish(wall)
        return row

    def __iter__(self) -> Any:
        def generate() -> Any:
            started = time.perf_counter()
            try:
                yield from self._relation
            finally:
                self._finish(time.perf_counter() - started)
        return generate()

    def arrow(self) -> Any:
        started = time.perf_counter()
        try:
            value = self._relation.arrow()
        finally:
            wall = time.perf_counter() - started
        self._finish(wall)
        return value

    def df(self) -> Any:
        started = time.perf_counter()
        try:
            value = self._relation.df()
        finally:
            wall = time.perf_counter() - started
        self._finish(wall)
        return value

    def fetchnumpy(self) -> Any:
        started = time.perf_counter()
        try:
            value = self._relation.fetchnumpy()
        finally:
            wall = time.perf_counter() - started
        self._finish(wall)
        return value


class ConnectionProxy:
    """Times each statement and reads its JSON profile after the result is consumed.

    The tool mixes three call styles: `execute(sql).fetchall()`, `execute(statement)` for
    DDL/SET, and `sql(sql).fetchall()` for lazy SELECTs. DuckDB executes the SELECT inside
    the fetch, so the profile is read only from the fetch path.
    """

    def __init__(self, connection: Any, recorder: Recorder) -> None:
        object.__setattr__(self, "_connection", connection)
        object.__setattr__(self, "_recorder", recorder)
        object.__setattr__(self, "_pending", None)
        object.__setattr__(self, "_closed", False)
        try:
            connection.execute("PRAGMA enable_profiling='json'")
        except Exception:
            pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)

    def __enter__(self) -> "ConnectionProxy":
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        self._finish_pending(None)
        return self._connection.__exit__(exc_type, exc, tb)

    def close(self) -> None:
        self._finish_pending(None)
        object.__setattr__(self, "_closed", True)
        self._connection.close()

    def cursor(self) -> "ConnectionProxy":
        return ConnectionProxy(self._connection.cursor(), self._recorder)

    def _rotate_profile(self) -> Path | None:
        path = self._recorder.next_profile_path()
        try:
            self._connection.execute("PRAGMA profiling_output=" + _sql_literal(path))
        except Exception:
            return None
        return path

    def _describe(self, query: Any) -> tuple[str, str, bool]:
        duckdb = _duckdb_module()
        if isinstance(query, str):
            try:
                statements = self._connection.extract_statements(query)
            except Exception:
                statements = []
            if len(statements) == 1:
                kind = getattr(statements[0].type, "name", str(statements[0].type))
                return query, kind, statements[0].type == duckdb.StatementType.SELECT
            return query, "MULTI", False
        sql = getattr(query, "query", None) or str(query)
        kind_value = getattr(query, "type", None)
        kind = getattr(kind_value, "name", str(kind_value))
        return sql, kind, kind_value == duckdb.StatementType.SELECT

    def _record(self, sql: str, statement_type: str, source: str, execute_wall: float,
                fetch_wall: float | None, path: Path | None) -> None:
        document = self._recorder.read_profile(path)
        head = " ".join(sql.split())
        self._recorder.record_statement({
            "source": source,
            "statement_type": statement_type,
            "sql_head": head[:200],
            "sql_sha1": hashlib.sha1(sql.encode("utf-8", "replace")).hexdigest(),
            "wall_execute_s": execute_wall,
            "wall_fetch_s": fetch_wall,
            "wall_total_s": execute_wall + (fetch_wall or 0.0),
            "profile": _profile_summary(document) if document else None,
        })

    def _finish_pending(self, fetch_wall: float | None) -> None:
        pending = self._pending
        if pending is None:
            return
        object.__setattr__(self, "_pending", None)
        self._record(pending["sql"], pending["statement_type"], pending["source"],
                     pending["execute_wall"], fetch_wall, pending["path"])

    def execute(self, query: Any, *args: Any, **kwargs: Any) -> "ConnectionProxy":
        sql, statement_type, is_select = self._describe(query)
        path = self._rotate_profile()
        started = time.perf_counter()
        try:
            self._connection.execute(query, *args, **kwargs)
        except BaseException:
            self._record(sql, statement_type, "execute", time.perf_counter() - started,
                         None, path)
            raise
        wall = time.perf_counter() - started
        if is_select:
            object.__setattr__(self, "_pending", {
                "sql": sql, "statement_type": statement_type, "source": "execute",
                "execute_wall": wall, "path": path,
            })
        else:
            # SET VARIABLE is profiled; CREATE VIEW and plain CREATE are not.
            self._record(sql, statement_type, "execute", wall, None, path)
        return self

    def fetchall(self) -> list[Any]:
        started = time.perf_counter()
        try:
            rows = self._connection.fetchall()
        finally:
            wall = time.perf_counter() - started
        self._finish_pending(wall)
        return rows

    def fetchone(self) -> Any:
        started = time.perf_counter()
        row = self._connection.fetchone()
        wall = time.perf_counter() - started
        if row is None:
            self._finish_pending(wall)
        return row

    def __iter__(self) -> Any:
        def generate() -> Any:
            started = time.perf_counter()
            try:
                yield from self._connection
            finally:
                self._finish_pending(time.perf_counter() - started)
        return generate()

    def sql(self, query: Any, *args: Any, **kwargs: Any) -> RelationProxy:
        sql, statement_type, _ = self._describe(query)
        path = self._rotate_profile()
        relation = self._connection.sql(query, *args, **kwargs)
        return RelationProxy(relation, self, path, sql, statement_type)


def install_duckdb_proxy(recorder: Recorder) -> Callable[[], None]:
    duckdb = _duckdb_module()
    original = duckdb.connect

    def connect(*args: Any, **kwargs: Any) -> ConnectionProxy:
        return ConnectionProxy(original(*args, **kwargs), recorder)

    duckdb.connect = connect
    return lambda: setattr(duckdb, "connect", original)


def install_run_probe(recorder: Recorder) -> Callable[[], None]:
    import uprof_native

    original = uprof_native.run

    # Modules loaded by the plain repetitions already bound `run` with
    # `from uprof_native import run`, so patching the defining module alone would miss them.
    rebound = [module for name, module in list(sys.modules.items())
               if name.startswith("uprof_") and getattr(module, "run", None) is original]

    def run(command: Any, *args: Any, **kwargs: Any) -> Any:
        label = _command_label(command)
        started = time.perf_counter()
        try:
            completed = original(command, *args, **kwargs)
        except BaseException as exc:
            recorder.subprocesses.append({
                "label": label, "argv0": str(command[0]), "elapsed_s": time.perf_counter() - started,
                "returncode": None, "error": type(exc).__name__,
            })
            raise
        recorder.subprocesses.append({
            "label": label, "argv0": str(command[0]), "elapsed_s": time.perf_counter() - started,
            "returncode": completed.returncode,
        })
        return completed

    uprof_native.run = run
    for module in rebound:
        module.run = run

    def restore() -> None:
        uprof_native.run = original
        for module in rebound:
            module.run = original

    return restore


# ---------------------------------------------------------------- stage extraction

def _stage_entries(prof_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    stats = pstats.Stats(str(prof_path))
    entries: list[dict[str, Any]] = []
    for (file_name, line, func), (_cc, ncalls, tottime, cumtime, _callers) in stats.stats.items():
        entries.append({
            "func": func, "file": os.path.basename(file_name), "line": line,
            "ncalls": ncalls, "tottime_s": tottime, "cumtime_s": cumtime,
        })
    entries.sort(key=lambda entry: entry["cumtime_s"], reverse=True)
    top = [entry for entry in entries
           if not entry["file"].startswith(("profile.py", "pstats.py"))][:20]
    grouped: dict[str, dict[str, Any]] = {}
    for func, file_part, label in STAGE_FUNCTIONS:
        for entry in entries:
            if entry["func"] != func or (file_part and file_part not in entry["file"]):
                continue
            bucket = grouped.setdefault(label, {
                "stage": label, "funcs": [], "ncalls": 0, "tottime_s": 0.0,
                "cumtime_s": 0.0,
            })
            if func not in bucket["funcs"]:
                bucket["funcs"].append(func)
            bucket["ncalls"] += entry["ncalls"]
            bucket["tottime_s"] += entry["tottime_s"]
            # Nested functions may share a label; the enclosing call is the stage's time.
            bucket["cumtime_s"] = max(bucket["cumtime_s"], entry["cumtime_s"])
    stages = sorted(grouped.values(), key=lambda entry: entry["cumtime_s"], reverse=True)
    return stages, top


# ---------------------------------------------------------------- running cases

def _call_main(argv: list[str]) -> tuple[int | None, str | None]:
    import uprof
    try:
        return int(uprof.main(argv) or 0), None
    except SystemExit as exc:
        return (int(exc.code) if isinstance(exc.code, int) else 1), "SystemExit"
    except BaseException:
        return None, traceback.format_exc()


def _build_argv(case: str, session: Path, out_file: Path | None, work_dir: Path,
                rep: int, seconds: int) -> list[str]:
    if case in CASE_BY_SCOPE:
        assert out_file is not None
        return ["profile", "--session", str(session), "--by", CASE_BY_SCOPE[case],
                "--out-file", str(out_file)]
    if case == "translate":
        return ["translate", "--session", str(session), "--out-dir", str(work_dir / "translate"),
                "--force"]
    if case == "translate-ascii":
        return ["translate", "--session", str(session),
                "--out-dir", str(work_dir / "translate-ascii"),
                "--ascii", "ibsop-event-dump", "--force"]
    if case == "collect":
        return ["collect", "--out-dir", str(work_dir / f"collect-{rep}"),
                "--seconds", str(seconds)]
    raise ValueError(f"unknown case {case}")


def _execute_once(argv: list[str], instrumented: bool, recorder: Recorder | None,
                  prof_path: Path | None) -> dict[str, Any]:
    sink_out, sink_err = _Sink(), _Sink()
    old_out, old_err = sys.stdout, sys.stderr
    restores: list[Callable[[], None]] = []
    profiler: cProfile.Profile | None = None
    started = time.perf_counter()
    cpu_before = _cpu_times()
    process_before = time.process_time()
    wall = 0.0
    try:
        sys.stdout, sys.stderr = sink_out, sink_err
        if instrumented:
            assert recorder is not None
            restores.append(install_duckdb_proxy(recorder))
            restores.append(install_run_probe(recorder))
            profiler = cProfile.Profile()
            profiler.enable()
        try:
            code, failure = _call_main(argv)
        finally:
            if profiler is not None:
                profiler.disable()
            wall = time.perf_counter() - started
    finally:
        for restore in reversed(restores):
            restore()
        sys.stdout, sys.stderr = old_out, old_err
    cpu_after = _cpu_times()
    process_cpu = time.process_time() - process_before
    stdout_bytes = sink_out.bytes_value()
    stderr_bytes = sink_err.bytes_value()
    result: dict[str, Any] = {
        "wall_s": wall,
        "exit_code": code,
        "failure": failure,
        "process_cpu_s": process_cpu,
        "process_cpu_ratio": process_cpu / wall if wall > 0 else None,
        "system_cpu_percent_during_rep": _system_cpu_percent(cpu_before, cpu_after),
        "stdout_sha256": _sha256_bytes(stdout_bytes),
        "stdout_bytes": len(stdout_bytes),
        "stderr_sha256": _sha256_bytes(stderr_bytes),
        "stderr_tail": stderr_bytes.decode("utf-8", "replace")[-4000:],
    }
    if prof_path is not None:
        profiler.dump_stats(str(prof_path))
        result["prof_file"] = str(prof_path)
    return result


def _dump_identity(root: Path) -> dict[str, Any] | None:
    if not root.exists():
        return None
    candidates = sorted(root.rglob("IbsOpDump.csv"),
                        key=lambda path: path.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    path = candidates[0]
    return {"path": str(path), "bytes": path.stat().st_size, "rows": _row_count(path),
            "sha256": _sha256_file(path)}


def _rep_output(result: dict[str, Any], out_file: Path) -> None:
    result["output_sha256"] = _sha256_file(out_file) if out_file.is_file() else \
        result["stdout_sha256"]
    result["output_bytes"] = out_file.stat().st_size if out_file.is_file() else \
        result["stdout_bytes"]


def run_case(case: str, args: argparse.Namespace, work_root: Path, tools_dir: Path,
             session: Path) -> dict[str, Any]:
    case_work = work_root / case
    case_work.mkdir(parents=True, exist_ok=True)

    # Warmups are plain runs excluded from the statistics. Only profile cases take them: the
    # first one generates the cache dump, while a translate warmup would cost another full copy.
    warmup_reps: list[dict[str, Any]] = []
    for rep in range(args.warmup if case in CASE_BY_SCOPE else 0):
        out_file = case_work / f"warmup-{rep}.out"
        argv = _build_argv(case, session, out_file, case_work, rep, args.seconds)
        result = _execute_once(argv, instrumented=False, recorder=None, prof_path=None)
        result["rep"] = rep
        _rep_output(result, out_file)
        warmup_reps.append(result)

    plain_reps: list[dict[str, Any]] = []
    dump_outputs: list[dict[str, Any]] = []
    reduced = False
    for rep in range(args.reps):
        out_file = case_work / f"plain-{rep}.out"
        argv = _build_argv(case, session, out_file, case_work, rep, args.seconds)
        result = _execute_once(argv, instrumented=False, recorder=None, prof_path=None)
        result["rep"] = rep
        if case == "translate-ascii":
            result["dump_output"] = _dump_identity(case_work / "translate-ascii")
            if result["dump_output"]:
                dump_outputs.append(result["dump_output"])
        _rep_output(result, out_file)
        plain_reps.append(result)
        if result["wall_s"] > args.per_rep_stop_seconds:
            reduced = True
        if reduced and len(plain_reps) >= 3:
            break

    identity_asserted = case in CASE_BY_SCOPE
    plain = {
        "reps": plain_reps,
        "wall": _summarize(rep["wall_s"] for rep in plain_reps),
        "exit_codes": [rep["exit_code"] for rep in plain_reps],
        "output_hashes": [rep["output_sha256"] for rep in plain_reps],
        "identical": len({rep["output_sha256"] for rep in plain_reps}) == 1,
        "identity_asserted": identity_asserted,
        "all_zero_exit": all(rep["exit_code"] == 0 for rep in plain_reps),
        "requested_reps": args.reps,
        "reduced_reps": reduced,
        "reduced_reason": ("a plain rep exceeded the per-rep stop; the case was cut to 3 reps"
                           if reduced else None),
    }

    instrumented_reps: list[dict[str, Any]] = []
    for rep in range(args.instrumented_reps):
        out_file = case_work / f"instrumented-{rep}.out"
        argv = _build_argv(case, session, out_file, case_work, rep, args.seconds)
        recorder = Recorder(case_work / f"rec-{rep}", keep_profiles=args.keep_prof)
        prof_path = case_work / f"instrumented-{rep}.prof"
        result = _execute_once(argv, instrumented=True, recorder=recorder, prof_path=prof_path)
        result["rep"] = rep
        if case == "translate-ascii":
            result["dump_output"] = _dump_identity(case_work / "translate-ascii")
            if result["dump_output"]:
                dump_outputs.append(result["dump_output"])
        _rep_output(result, out_file)
        stages, top = _stage_entries(prof_path)
        result["stages"] = stages
        result["top_functions"] = top
        result["duckdb"] = _duckdb_summary(recorder.statements)
        result["subprocesses"] = _subprocess_summary(recorder.subprocesses)
        instrumented_reps.append(result)
        if args.keep_prof:
            destination = Path(args.out).with_suffix(".prof")
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(prof_path, destination / f"{case}-instr-{rep}.prof")
            shutil.copytree(recorder.profile_dir,
                            destination / f"duckprof-{case}-{rep}", dirs_exist_ok=True)

    matches_plain = None
    if identity_asserted:
        matches_plain = bool(instrumented_reps and plain["identical"] and
                             all(rep["output_sha256"] == plain["output_hashes"][0]
                                 for rep in instrumented_reps))
    return {
        "case": case,
        "warmup": warmup_reps,
        "plain": plain,
        "instrumented": instrumented_reps,
        "instrumented_matches_plain": matches_plain,
        "dump_outputs": dump_outputs,
        "dump_outputs_identical": bool(dump_outputs) and
                                  len({entry["sha256"] for entry in dump_outputs}) == 1,
    }


def _duckdb_summary(statements: list[dict[str, Any]]) -> dict[str, Any]:
    profiled = [record for record in statements if record.get("profile")]
    by_type: dict[str, dict[str, Any]] = {}
    for record in statements:
        bucket = by_type.setdefault(record["statement_type"], {"count": 0, "wall_s": 0.0})
        bucket["count"] += 1
        bucket["wall_s"] += record["wall_total_s"]
    csv_scan_s = sum(scan.get("timing_s") or 0.0
                     for record in profiled for scan in record["profile"]["csv_scans"])
    return {
        "statements": len(statements),
        "profiled_statements": len(profiled),
        "wall_s_sum": sum(record["wall_total_s"] for record in statements),
        "query_total_s_sum": sum(record["profile"]["query_total_s"] or 0.0
                                 for record in profiled),
        "query_cpu_s_sum": sum(record["profile"]["query_cpu_s"] or 0.0 for record in profiled),
        "bytes_read_sum": sum(record["profile"]["bytes_read"] or 0 for record in profiled),
        "rows_scanned_sum": sum(record["profile"]["rows_scanned"] or 0 for record in profiled),
        "csv_scan_s_sum": csv_scan_s,
        "by_statement_type": by_type,
        "records": statements,
    }


def _subprocess_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_label: dict[str, list[float]] = {}
    for record in records:
        by_label.setdefault(record["label"], []).append(record["elapsed_s"])
    return {
        "count": len(records),
        "wall_s_sum": sum(record["elapsed_s"] for record in records),
        "by_label": {
            label: {"count": len(values), "wall_s_sum": sum(values),
                    "wall_s_median": statistics.median(values)}
            for label, values in sorted(by_label.items())
        },
        "records": records,
    }


# ---------------------------------------------------------------- report

def _present_median(records: Iterable[dict[str, Any]], key: str) -> float | None:
    values = [record.get(key) for record in records if record.get(key) is not None]
    return statistics.median(values) if values else None


def _markdown(results: dict[str, Any]) -> str:
    identity = results.get("session_after") or results["session"]
    dump_text = (f"{identity['dump_rows']} rows, {identity['dump_bytes']} bytes"
                 if identity.get("dump_rows") is not None else "no dump at start")
    lines = [
        f"# Baseline timing ({results['git']['head']})",
        "",
        f"Session: `{identity['session']}` — {dump_text}",
        "",
        "| case | reps | median s | p95 s | min s | max s | sys CPU % med | proc/wall med "
        "| identical |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for name, case in results["cases"].items():
        wall = case["plain"]["wall"]
        if not wall.get("count"):
            continue
        reps = case["plain"]["reps"]
        cpu = _present_median(reps, "system_cpu_percent_during_rep")
        ratio = _present_median(reps, "process_cpu_ratio")
        lines.append(
            f"| {name} | {wall['count']} | {wall['median_s']:.3f} | {wall['p95_s']:.3f} | "
            f"{wall['min_s']:.3f} | {wall['max_s']:.3f} | "
            f"{f'{cpu:.1f}' if cpu is not None else 'n/a'} | "
            f"{f'{ratio:.2f}' if ratio is not None else 'n/a'} | "
            f"{case['plain']['identical']} |")

    for name, case in results["cases"].items():
        if name == "collect" and case["plain"]["wall"].get("count"):
            median = case["plain"]["wall"]["median_s"]
            lines += ["", f"collect includes the requested {results['config']['seconds']} s "
                          f"capture; median overhead {median - results['config']['seconds']:.3f} s."]

    session_after = results.get("session_after") or {}
    if results.get("dump_generated") and session_after.get("dump"):
        lines += ["", "## Cold dump generation", "",
                  f"- dump: `{session_after['dump']}`",
                  f"- rows: {session_after['dump_rows']}",
                  f"- bytes: {session_after['dump_bytes']}",
                  f"- sha256: `{session_after['dump_sha256']}`"]
        for name, case in results["cases"].items():
            for rep in case.get("warmup", []):
                lines.append(f"- warmup {name} rep {rep['rep']}: {rep['wall_s']:.3f} s "
                             "(includes the profile run)")

    for name, case in results["cases"].items():
        outputs = case.get("dump_outputs") or []
        if outputs:
            first = outputs[0]
            lines += ["", f"### {name} dump output", "",
                      f"- identical across reps: {case['dump_outputs_identical']}",
                      f"- rows: {first['rows']}",
                      f"- bytes: {first['bytes']}",
                      f"- sha256: `{first['sha256']}`"]

    instrumented = [(name, case["instrumented"][0]) for name, case in results["cases"].items()
                    if case["instrumented"]]
    if instrumented:
        lines += ["", "## Instrumented stage totals", ""]
        for name, record in instrumented:
            duck = record["duckdb"]
            sub = record["subprocesses"]
            lines.append(f"### {name}")
            lines.append("")
            lines.append(f"wall {record['wall_s']:.3f} s; DuckDB statements "
                         f"{duck['statements']} ({duck['profiled_statements']} profiled), "
                         f"query total {duck['query_total_s_sum']:.3f} s, "
                         f"CSV scans {duck['csv_scan_s_sum']:.3f} s, "
                         f"{duck['bytes_read_sum']} bytes read; "
                         f"children {sub['count']} totalling {sub['wall_s_sum']:.3f} s")
            lines.append("")
            lines.append("| stage | calls | tottime s | cumtime s |")
            lines.append("|---|---:|---:|---:|")
            for stage in record["stages"]:
                lines.append(f"| {stage['stage']} | {stage['ncalls']} | "
                             f"{stage['tottime_s']:.3f} | {stage['cumtime_s']:.3f} |")
            lines.append("")
    return "\n".join(lines) + "\n"


def _refresh_session(results: dict[str, Any], session: Path, force: bool = False) -> None:
    after = results.get("session_after") or {}
    if force or (results["session"]["dump"] is None and not after.get("dump")):
        results["session_after"] = _session_identity(session)
    after = results.get("session_after") or {}
    results["dump_generated"] = bool(results["session"]["dump"] is None and after.get("dump"))


def _cold_dump(results: dict[str, Any]) -> dict[str, Any] | None:
    if not results.get("dump_generated"):
        return None
    after = results["session_after"]
    base = {"dump": after["dump"], "dump_rows": after["dump_rows"],
            "dump_bytes": after["dump_bytes"], "dump_sha256": after["dump_sha256"],
            "note": "the warmup wall includes the profile run that triggered generation"}
    for name, case in results["cases"].items():
        warmup = case.get("warmup") or []
        if warmup:
            return {"case": name, "warmup_wall_s": warmup[0]["wall_s"],
                    "warmup_reps": warmup, **base}
    return {"case": None, **base}


def _write_outputs(results: dict[str, Any], out_path: Path) -> None:
    results["cold_dump"] = _cold_dump(results)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    out_path.with_suffix(".md").write_text(_markdown(results), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True, help="session directory to profile")
    parser.add_argument("--out", required=True, help="results JSON path")
    parser.add_argument("--cases", default=DEFAULT_CASES,
                        help=f"comma-separated cases; default {DEFAULT_CASES}")
    parser.add_argument("--reps", type=int, default=5, help="plain repetitions (default 5)")
    parser.add_argument("--instrumented-reps", type=int, default=1,
                        help="instrumented repetitions (default 1)")
    parser.add_argument("--seconds", type=int, default=60,
                        help="collect capture duration (default 60)")
    parser.add_argument("--warmup", type=int, default=0,
                        help="extra plain reps per profile case before the timed ones (default 0)")
    parser.add_argument("--per-rep-stop-seconds", type=float, default=480.0,
                        help="a plain rep longer than this cuts its case to 3 reps (default 480)")
    parser.add_argument("--max-total-minutes", type=float, default=0.0,
                        help="stop before the next case after this many minutes (default: no cap)")
    parser.add_argument("--tools-dir", default=None,
                        help="directory holding uprof.py; default "
                             "plugin/skills/amd-uprof/tools")
    parser.add_argument("--keep-prof", action="store_true",
                        help="keep DuckDB JSON profiles and copy cProfile dumps beside --out")
    args = parser.parse_args(argv)

    session = Path(args.session).resolve()
    if not (session / "session.uprof").is_file():
        print(f"error: {session} has no session.uprof", file=sys.stderr)
        return 2
    if not (session / "cpu.db").is_file():
        print(f"error: {session} has no cpu.db", file=sys.stderr)
        return 2
    cases = [case.strip() for case in args.cases.split(",") if case.strip()]
    unknown = [case for case in cases if case not in ALL_CASES]
    if unknown:
        print(f"error: unknown case(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    repo = Path(__file__).resolve().parents[1]
    tools_dir = (Path(args.tools_dir).resolve() if args.tools_dir
                 else repo / "plugin" / "skills" / "amd-uprof" / "tools")
    if not (tools_dir / "uprof.py").is_file():
        print(f"error: {tools_dir} has no uprof.py", file=sys.stderr)
        return 2
    sys.path.insert(0, str(tools_dir))
    import uprof  # noqa: F401  (imports the sibling modules from tools_dir)

    import uprof_native
    results: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_utc": _utc_now(),
        "host": _host_snapshot(),
        "versions": {
            "python": sys.version.split()[0],
            "duckdb": __import__("duckdb").__version__,
            "uprof_cli": _run_version([str(path)] + ["--version"]
                                      if (path := uprof_native.find_uprof()) else None),
            "llvm": _run_version([str(path), "--version"]
                                 if (path := uprof_native.find_symbolizer()) else None),
        },
        "git": {
            "head": _git(repo, "rev-parse", "HEAD"),
            "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        },
        "session": _session_identity(session),
        "config": {
            "tools_dir": str(tools_dir), "cases": cases, "reps": args.reps,
            "instrumented_reps": args.instrumented_reps, "warmup": args.warmup,
            "seconds": args.seconds, "per_rep_stop_seconds": args.per_rep_stop_seconds,
            "max_total_minutes": args.max_total_minutes,
        },
        "stopped_early": None,
        "cases": {},
    }

    out_path = Path(args.out)
    started = time.perf_counter()
    work_root = Path(tempfile.mkdtemp(prefix="uprof-timing-"))
    try:
        for case in cases:
            elapsed_minutes = (time.perf_counter() - started) / 60.0
            if args.max_total_minutes and elapsed_minutes >= args.max_total_minutes:
                results["stopped_early"] = {
                    "case": case, "elapsed_minutes": elapsed_minutes,
                    "reason": f"max-total-minutes {args.max_total_minutes}",
                }
                print(f"[timing] stopping before {case}: {results['stopped_early']['reason']}",
                      file=sys.stderr)
                break
            print(f"[timing] {case}: {args.reps} plain, {args.instrumented_reps} instrumented, "
                  f"{args.warmup if case in CASE_BY_SCOPE else 0} warmup", file=sys.stderr)
            results["cases"][case] = run_case(case, args, work_root, tools_dir, session)
            _refresh_session(results, session)
            _write_outputs(results, out_path)
            case_result = results["cases"][case]
            print(f"[timing] {case}: median {case_result['plain']['wall'].get('median_s', 0):.3f}s "
                  f"p95 {case_result['plain']['wall'].get('p95_s', 0):.3f}s "
                  f"identical={case_result['plain']['identical']} "
                  f"all_zero_exit={case_result['plain']['all_zero_exit']} "
                  f"elapsed={elapsed_minutes:.1f}min", file=sys.stderr)
    finally:
        shutil.rmtree(work_root, ignore_errors=True)

    _refresh_session(results, session, force=True)
    _write_outputs(results, out_path)
    print(_markdown(results))
    print(f"[timing] wrote {out_path} and {out_path.with_suffix('.md')}", file=sys.stderr)

    failures = [name for name, case in results["cases"].items()
                if not case["plain"]["all_zero_exit"]]
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
