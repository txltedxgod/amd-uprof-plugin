"""Per-session DuckDB cache for the symbol and function-range artifacts.

One database file per capture session. The capture connection is opened read-only by
uprof_db; this module attaches the cache to it read-only for lookups and read-write while an
artifact is stored or a cached artifact is read. DuckDB allows one writer per database file,
so attach and store retry with a bounded backoff and any cache failure degrades to the
uncached path instead of failing the profile.

Artifacts are tables, not files: symbols, publics, pdbs and ranges are keyed by a run key that
covers the capture-side module identity (path, size, checksum, 32/64-bit, debug-info flag), the
queried RVAs, the on-disk image state, the tool builds and the derivation version. A changed
binary, PDB, tool or query scope therefore misses and re-derives instead of serving stale rows.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Final, TextIO

import uprof_db
import uprof_symbols
from uprof_context import find_readobj
from uprof_native import (IS_WINDOWS, default_symbol_servers, find_sibling, find_symbolizer,
                          symbol_cache_dir)
from uprof_util import contains

TOOLS_DIR: Final = Path(os.path.abspath(__file__)).parent

CACHE_ALIAS = "uprof_cache"
SCHEMA_VERSION = 3
# The only files the cache owns in its root: cache_db_path names and their quarantined copies.
_CACHE_NAME = re.compile(r"[0-9a-f]{32}\.duckdb")
_CORRUPT_NAME = re.compile(r"[0-9a-f]{32}\.duckdb\.corrupt")
# Everything the session cache writes into its root: databases, WAL and temp files, corrupt copies.
_OWN_ENTRY = re.compile(r"[0-9a-f]{32}\.duckdb(\..*)?", re.IGNORECASE)


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) else default


ATTACH_TIMEOUT_S = _env_float("UPROF_SESSION_CACHE_TIMEOUT", 30.0)
MAX_BYTES = int(_env_float("UPROF_SESSION_CACHE_MAX_MB", 1024.0) * 1024 * 1024)
TTL_DAYS = _env_float("UPROF_SESSION_CACHE_TTL_DAYS", 7.0)
DISABLE = os.environ.get("UPROF_SESSION_CACHE_DISABLE", "").strip().lower() in (
    "1", "true", "yes", "on")
_CREDENTIALS = re.compile(r"(?i)([a-z]+://)[^@\s/]+@")
_CLEANED = False


def cache_root() -> Path:
    override = os.environ.get("UPROF_SESSION_CACHE_ROOT")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"))
        return base / "Symbols" / "uprof-session-cache"
    base = Path(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"))
    return base / "amd-uprof" / "session-cache"


def cache_db_path(session: Path) -> Path:
    cpu_db = session / "cpu.db"
    parts = [str(session.resolve())]
    try:
        stat = cpu_db.stat()
        parts.extend([str(stat.st_size), str(stat.st_mtime_ns)])
    except OSError:
        parts.append("missing")
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]
    return cache_root() / f"{digest}.duckdb"


def _file_identity(path: object) -> list[object]:
    if not path:
        return [None, None, None]
    try:
        resolved = Path(str(path)).resolve()
        stat = resolved.stat()
        return [str(resolved), stat.st_size, stat.st_mtime_ns]
    except OSError:
        return [str(path), None, None]


def tool_identities() -> dict[str, list[object]]:
    symbolizer = find_symbolizer()
    return {
        "symbolizer": _file_identity(symbolizer),
        "pdbutil": _file_identity(find_sibling(symbolizer, "llvm-pdbutil")),
        "readobj": _file_identity(find_readobj()),
    }


def _dir_identity(path: Path) -> list[object]:
    try:
        return [str(path), Path(path).stat().st_mtime_ns]
    except OSError:
        return [str(path), None]


def _files_in(directory: Path, names: set[str] | None = None,
              limit: int = 4096) -> list[list[object]]:
    """Identities of matching files in a directory; only matching names are stat'ed."""
    result: list[list[object]] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(result) >= limit:
                    break
                if names is not None and entry.name.lower() not in names:
                    continue
                if entry.is_file():
                    result.append(_file_identity(entry.path))
    except OSError:
        return []
    return result


def _dir_listing(path: Path, limit: int = 1024, holds_own: bool = False) -> list[object]:
    """A directory's mtime and child names; a newly staged PDB changes the names.

    holds_own marks a directory the session cache writes into: its own entries are left out and
    its mtime is not used, since storing a result must not change the key it is stored under.
    """
    try:
        with os.scandir(path) as entries:
            names = sorted(entry.name for entry in entries
                           if not (holds_own and _OWN_ENTRY.fullmatch(entry.name)))[:limit]
        return [str(path), None if holds_own else Path(path).stat().st_mtime_ns, names]
    except OSError:
        return [str(path), None, []]


def _srv_caches() -> list[list[object]]:
    """The cache directories named by _NT_SYMBOL_PATH srv* entries and their child listings.

    The session cache root may lie inside such a cache (the default one does); it is listed
    without the session cache's own files.
    """
    own = cache_root()
    try:
        own_stat = own.stat()
    except OSError:
        own_stat = None
    result: list[list[object]] = []
    for entry in os.environ.get("_NT_SYMBOL_PATH", "").split(";"):
        parts = entry.split("*")
        if len(parts) < 2 or parts[0].strip().lower() != "srv" or not parts[1].strip():
            continue
        root = Path(parts[1].strip())
        root_is_own = own_stat is not None and contains(own, root)
        result.append(_dir_listing(root, holds_own=root_is_own))
        try:
            for child in sorted(root.iterdir())[:256]:
                if root_is_own and _OWN_ENTRY.fullmatch(child.name):
                    continue
                if child.is_dir():
                    is_own = root_is_own or _same_dir(child, own_stat)
                    result.append(_dir_listing(child, 64, holds_own=is_own))
        except OSError:
            pass
    return result


def _same_dir(path: Path, other: os.stat_result | None) -> bool:
    if other is None:
        return False
    try:
        return os.path.samestat(path.stat(), other)
    except OSError:
        return False


def search_identity(symbol_path: list[str] | None, image_path: list[str] | None,
                    module_names: list[str] = ()) -> dict[str, object]:
    """The symbol/image search state a hit must be validated against.

    Explicit files and directories are fingerprinted, a directory's own mtime catches files
    appearing beside a module, and the symbol cache root and any srv* cache directories catch a
    newly staged PDB.
    """
    paths = uprof_symbols.probe_paths(symbol_path, image_path)
    names = {Path(name).name.lower() for name in module_names if name}
    names |= {Path(name).stem.lower() + ".pdb" for name in module_names if name}
    module_dirs = sorted({str(Path(name).parent) for name in module_names
                          if name and Path(name).is_absolute()})
    return {
        "symbol_files": [_file_identity(path) for path in paths.symbol_files],
        "symbol_dirs": [_dir_identity(path) for path in paths.symbol_dirs],
        "symbol_dir_files": [entry for path in paths.symbol_dirs
                             for entry in _files_in(path, names)],
        "image_files": [_file_identity(path) for path in paths.image_files],
        "image_dirs": [_dir_identity(path) for path in paths.image_dirs],
        "image_dir_files": [entry for path in paths.image_dirs
                            for entry in _files_in(path, names)],
        "module_dirs": [_dir_identity(Path(path)) for path in module_dirs],
        "srv_caches": _srv_caches(),
        "nt_symbol_path": os.environ.get("_NT_SYMBOL_PATH", ""),
        "symbol_servers": list(default_symbol_servers()),
    }


def _disk_identity(paths: list[str]) -> list[list[object]]:
    result: list[list[object]] = []
    for path in sorted(set(paths)):
        try:
            stat = Path(path).stat()
            result.append([path, True, stat.st_size, stat.st_mtime_ns])
        except OSError:
            result.append([path, False, None, None])
    return result


def module_identity_rows(connection: object, names: list[str]) -> list[list[object]]:
    """Distinct capture-side identities for the named modules, ordered for a stable key.

    A capture without the identity columns falls back to the columns it has; the key then
    relies on the on-disk identity, which the caller includes alongside these rows.
    """
    names = sorted(set(names))
    if not names:
        return []
    columns = {str(row[0]).lower() for row in connection.execute(
        "SELECT column_name FROM duckdb_columns() WHERE lower(table_name) = 'module'").fetchall()}

    def column(name: str, kind: str) -> str:
        return f"CAST({name} AS {kind})" if name.lower() in columns else "NULL"

    select = ", ".join(("COALESCE(path, '')", column("size", "UBIGINT"),
                        column("checksum", "UBIGINT"), column("is32Bit", "BOOLEAN"),
                        column("foundDebugInfo", "BOOLEAN")))
    placeholders = ", ".join("?" for _ in names)
    rows = connection.execute(
        f"SELECT DISTINCT {select} FROM Module "
        f"WHERE module_key(path) IN ({placeholders}) ORDER BY 1, 2, 3, 4, 5",
        names).fetchall()
    return [[str(row[0]), row[1], row[2], row[3], row[4]] for row in rows]


def ambiguous_modules(connection: object, names: list[str]) -> list[str]:
    """Names the capture maps to more than one image version.

    IBS dump rows carry the module name, not Module.id, so a name with two versions cannot be
    attributed per sample; the caller must not symbolize or cache those modules.
    """
    names = sorted({name for name in names if name})
    if not names:
        return []
    columns = {str(row[0]).lower() for row in connection.execute(
        "SELECT column_name FROM duckdb_columns() WHERE lower(table_name) = 'module'").fetchall()}
    keys = [name for name in ("size", "checksum", "is32Bit") if name in columns]
    distinct = (f"count(DISTINCT ({', '.join(keys)}))" if keys
                else "count(DISTINCT path)")
    placeholders = ", ".join("?" for _ in names)
    rows = connection.execute(
        f"SELECT module_key(path) AS name, {distinct} AS versions FROM Module "
        f"WHERE module_key(path) IN ({placeholders}) GROUP BY 1 HAVING versions > 1",
        names).fetchall()
    return sorted(str(row[0]) for row in rows)


def version_identity_verifiable(connection: object) -> bool:
    """Whether the capture records the columns needed to tell image versions apart."""
    columns = {str(row[0]).lower() for row in connection.execute(
        "SELECT column_name FROM duckdb_columns() WHERE lower(table_name) = 'module'").fetchall()}
    return all(name in columns for name in ("size", "checksum", "is32bit"))


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def symbol_key(rvas: list[tuple[str, str, str]], modules: list[list[object]],
               disk: list[list[object]], tools: dict[str, list[object]],
               search: dict[str, object]) -> str:
    return _digest({"version": SCHEMA_VERSION, "rvas": rvas, "modules": modules,
                    "disk": disk, "tools": tools, "search": search})


def build_symbols_key(connection: object, args: Any) -> tuple[str, list[tuple[str, str, str]]]:
    """The symbolization cache key and the (module, path, rva) rows it covers."""
    _, rows = uprof_db.fetch(connection, TOOLS_DIR / "profile-rvas.sql")
    rvas = [(str(row[0]), str(row[1]), str(row[2])) for row in rows]
    names = [name for name, _path, _rva in rvas]
    if names and not version_identity_verifiable(connection):
        raise ValueError(
            "the capture records no image size/checksum/bitness columns, so module version "
            "identity cannot be verified and the session cache is disabled")
    ambiguous = ambiguous_modules(connection, names)
    if ambiguous:
        raise ValueError(
            "module name(s) map to more than one image version: "
            + ", ".join(ambiguous)
            + "; IBS dump samples carry the module name, not Module.id, so per-version "
              "attribution is unavailable and the session cache is disabled")
    paths = [path for _name, path, _rva in rvas if path]
    key = symbol_key(
        rvas, module_identity_rows(connection, names), _disk_identity(paths),
        tool_identities(),
        search_identity(getattr(args, "symbol_path", None), getattr(args, "image_path", None),
                        names))
    return key, rvas


def ranges_key(modules: list[list[str]], identities: list[list[object]],
               disk: list[list[object]], readobj: list[object], symbols_key: str) -> str:
    return _digest({"version": SCHEMA_VERSION, "modules": modules, "identities": identities,
                    "disk": disk, "readobj": readobj, "symbols": symbols_key})


def build_ranges_key(connection: object, symbols_key: str) -> str:
    """The range-derivation cache key, bound to the symbolization state it consumes."""
    _, rows = uprof_db.fetch(connection, TOOLS_DIR / "profile-function-modules.sql")
    modules = [[str(row[0]), str(row[1] or "")] for row in rows]
    paths = [path for _name, path in modules if path]
    return ranges_key(
        modules, module_identity_rows(connection, [name for name, _path in modules]),
        _disk_identity(paths), tool_identities()["readobj"], symbols_key)


def _remove_db(path: Path) -> None:
    for candidate in (path, path.with_name(path.name + ".wal")):
        with contextlib.suppress(OSError):
            candidate.unlink(missing_ok=True)


def _storage_version_error(exc: BaseException) -> bool:
    """DuckDB refused the file because another DuckDB version wrote it; the file is intact."""
    text = str(exc).lower()
    return "storage version" in text or "newer version of duckdb" in text


def cleanup_orphans(root: Path | None = None) -> None:
    """Best-effort removal of cache databases that no live session digest can use.

    Only digest-named files are considered, and a file written by a newer cache schema or
    another DuckDB storage version is left to the version that owns it.
    """
    global _CLEANED
    if _CLEANED:
        return
    _CLEANED = True
    root = root or cache_root()
    if not root.is_dir():
        return
    cutoff = time.time() - TTL_DAYS * 86400
    for path in root.glob("*.duckdb"):
        if not _CACHE_NAME.fullmatch(path.name):
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        session_path = None
        version = None
        readable = False
        try:
            import duckdb
            connection = duckdb.connect(str(path), read_only=True)
            try:
                rows = connection.execute(
                    "SELECT max(version), any_value(session_path) FROM cache_meta").fetchall()
                version = rows[0][0] if rows else None
                session_path = str(rows[0][1]) if rows and rows[0][1] else None
                readable = True
            finally:
                connection.close()
        except Exception as exc:  # noqa: BLE001 - unreadable and old: an orphan candidate
            if _storage_version_error(exc):
                continue
            readable = False
        if readable and version is not None and int(version) > SCHEMA_VERSION:
            continue
        if not readable:
            if mtime <= cutoff:
                _remove_db(path)
            continue
        if session_path is None or not Path(session_path).is_dir():
            _remove_db(path)
            continue
        expected = cache_db_path(Path(session_path))
        try:
            if path.resolve() != expected.resolve():
                _remove_db(path)
        except OSError:
            pass
    for path in root.glob("*.duckdb.corrupt"):
        if not _CORRUPT_NAME.fullmatch(path.name):
            continue
        try:
            if path.stat().st_mtime <= cutoff:
                path.unlink(missing_ok=True)
        except OSError:
            pass


class SessionCache:
    """Attach, look up, store and expose the per-session artifact tables."""

    def __init__(self, connection: object, session: Path, stream: TextIO = sys.stderr,
                 timeout: float | None = None):
        self.connection = connection
        self.session = Path(session).resolve()
        self.path = cache_db_path(session)
        self.stream = stream
        self.timeout = ATTACH_TIMEOUT_S if timeout is None else timeout
        self.mode: str | None = None
        self.disabled = DISABLE
        self.busy = False
        cleanup_orphans()

    # ---------------------------------------------------------------- attachment

    def _warn(self, message: str) -> None:
        print(f"WARNING: session cache: {message}", file=self.stream)

    def disable(self, exc: object) -> None:
        if not self.disabled:
            self._warn(f"disabled ({exc}); profiling without the cache")
        self.disabled = True

    @staticmethod
    def _lock_error(exc: BaseException) -> bool:
        text = str(exc).lower()
        return ("lock" in text or "conflict" in text
                or "being used by another process" in text
                or "already open" in text or "already attached" in text)

    def _discard_corrupt(self, exc: BaseException) -> bool:
        """A disposable cache file that cannot be attached is moved aside once."""
        try:
            if not self.path.is_file():
                return False
            aside = self.path.with_name(self.path.name + ".corrupt")
            os.replace(self.path, aside)
            self._warn(f"cache could not be opened ({exc}); moved it to {aside}")
            return True
        except OSError:
            return False

    def _attach(self, read_only: bool) -> bool:
        if self.disabled or self.busy:
            return False
        mode = "READ_ONLY" if read_only else "READ_WRITE"
        quoted = str(self.path).replace("'", "''")
        deadline = time.monotonic() + self.timeout
        delay = 0.05
        retried = False
        while True:
            try:
                self.connection.execute(
                    f"ATTACH '{quoted}' AS {CACHE_ALIAS} ({mode})")
                self.mode = "ro" if read_only else "rw"
                return True
            except Exception as exc:  # noqa: BLE001 - cache failure degrades, never the profile
                if self._lock_error(exc):
                    if time.monotonic() < deadline:
                        time.sleep(delay)
                        delay = min(delay * 2, 1.0)
                        continue
                    self.busy = True
                    self._warn("cache is busy; profiling without it")
                    return False
                if _storage_version_error(exc):
                    self._warn(f"written by another DuckDB storage version ({exc}); "
                               "profiling without the cache")
                    self.disabled = True
                    return False
                if not retried and self._discard_corrupt(exc):
                    retried = True
                    if read_only and not self.path.is_file():
                        return False
                    continue
                self._warn(f"attach failed ({exc}); profiling without the cache")
                self.disabled = True
                return False

    def _detach(self) -> None:
        if self.mode is None:
            return
        try:
            self.connection.execute(f"DETACH {CACHE_ALIAS}")
        except Exception:  # noqa: BLE001 - a failed detach cannot change the result
            pass
        self.mode = None

    def ensure_read(self) -> bool:
        if self.disabled:
            return False
        if self.mode is not None:
            return True
        if not self.path.is_file():
            return False
        return self._attach(True)

    def ensure_write(self) -> bool:
        if self.disabled:
            return False
        if self.mode == "rw":
            return True
        if self.mode == "ro":
            self._detach()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._warn(f"cannot create {self.path.parent} ({exc}); profiling without the cache")
            self.disabled = True
            return False
        if not self._attach(False):
            return False
        return self._ensure_schema()

    def close(self) -> None:
        self._detach()

    def release(self) -> None:
        """Detach after the last store when no cache-backed views are live."""
        self._detach()

    def _ensure_schema(self) -> bool:
        try:
            self.connection.execute("BEGIN TRANSACTION")
            self.connection.execute(
                f"CREATE TABLE IF NOT EXISTS {CACHE_ALIAS}.cache_meta("
                "version INTEGER, session_path VARCHAR)")
            rows = self.connection.execute(
                f"SELECT max(version) FROM {CACHE_ALIAS}.cache_meta").fetchall()
            current = None if not rows else rows[0][0]
            if current is not None and int(current) > SCHEMA_VERSION:
                # A newer plugin owns this file; rebuilding would wipe its cache.
                self.connection.execute("ROLLBACK")
                self._warn(f"schema version {current} is newer than {SCHEMA_VERSION}; "
                           "profiling without the cache")
                self.disabled = True
                return False
            if current is not None and int(current) != SCHEMA_VERSION:
                self._warn(f"schema version {current} -> {SCHEMA_VERSION}; rebuilding")
                for table in ("symbols", "publics", "pdbs", "symbol_runs",
                              "ranges", "range_runs"):
                    self.connection.execute(f"DROP TABLE IF EXISTS {CACHE_ALIAS}.{table}")
                current = None
            tables = {
                "symbol_runs": "run_key VARCHAR PRIMARY KEY, created_at VARCHAR, "
                               "evidence VARCHAR, stderr VARCHAR, transient INTEGER, "
                               "pdb_identity VARCHAR, probe_identity VARCHAR",
                "symbols": "run_key VARCHAR, module_name VARCHAR, address VARCHAR, "
                           "function VARCHAR, function_short VARCHAR, "
                           "containing_function VARCHAR, file VARCHAR, line INTEGER",
                "publics": "run_key VARCHAR, module_name VARCHAR, rva VARCHAR, "
                           "name_count INTEGER, names VARCHAR",
                "pdbs": "run_key VARCHAR, module_name VARCHAR, pdb VARCHAR",
                "range_runs": "run_key VARCHAR PRIMARY KEY, created_at VARCHAR, "
                              "info VARCHAR, stderr VARCHAR",
                "ranges": "run_key VARCHAR, module_name VARCHAR, function_start VARCHAR, "
                          "function_end VARCHAR, function_source VARCHAR, "
                          "function_name VARCHAR",
            }
            for name, columns in tables.items():
                self.connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {CACHE_ALIAS}.{name}({columns})")
            if current is None:
                self.connection.execute(f"DELETE FROM {CACHE_ALIAS}.cache_meta")
                self.connection.execute(
                    f"INSERT INTO {CACHE_ALIAS}.cache_meta(version, session_path) "
                    "VALUES (?, ?)", [SCHEMA_VERSION, str(self.session)])
            else:
                self.connection.execute(
                    f"UPDATE {CACHE_ALIAS}.cache_meta SET session_path = ?", [str(self.session)])
            self.connection.execute("COMMIT")
            return True
        except Exception as exc:  # noqa: BLE001 - disable the cache, keep the profile
            with contextlib.suppress(Exception):
                self.connection.execute("ROLLBACK")
            self._warn(f"schema setup failed ({exc}); profiling without the cache")
            self.disabled = True
            return False

    def _repair(self, exc: BaseException) -> bool:
        """Recover from a missing/broken schema left by an interrupted first store."""
        self._detach()
        if self.ensure_write():
            return True
        self._warn(f"schema repair failed ({exc}); profiling without the cache")
        self.disabled = True
        return False

    # ------------------------------------------------------------------ lookups

    def lookup(self, table: str, run_key: str) -> bool:
        if not self.ensure_read():
            return False
        query = f"SELECT 1 FROM {CACHE_ALIAS}.{table} WHERE run_key = ?"
        try:
            rows = self.connection.execute(query, [run_key]).fetchall()
        except Exception as exc:  # noqa: BLE001 - repair once, then keep the profile
            if not self._repair(exc):
                return False
            try:
                rows = self.connection.execute(query, [run_key]).fetchall()
            except Exception as retry:  # noqa: BLE001
                self._warn(f"lookup failed ({retry}); profiling without the cache")
                self.disabled = True
                return False
        return bool(rows)

    @staticmethod
    def _identity_matches(identity: dict[str, object]) -> bool:
        try:
            stat = Path(str(identity["path"])).stat()
        except (OSError, KeyError, TypeError):
            return "exists" in identity and identity.get("exists") is False
        if identity.get("exists") is False:
            return False
        return (stat.st_size == identity.get("size")
                and stat.st_mtime_ns == identity.get("mtime_ns"))

    def symbols_valid(self, run_key: str) -> bool:
        """A hit is served only when its resolved PDBs and probed paths still match."""
        if not self.ensure_read():
            return False
        query = (f"SELECT transient, pdb_identity, probe_identity FROM {CACHE_ALIAS}.symbol_runs "
                 "WHERE run_key = ?")
        try:
            rows = self.connection.execute(query, [run_key]).fetchall()
        except Exception as exc:  # noqa: BLE001
            if not self._repair(exc):
                return False
            try:
                rows = self.connection.execute(query, [run_key]).fetchall()
            except Exception as retry:  # noqa: BLE001
                self._warn(f"validation failed ({retry}); profiling without the cache")
                self.disabled = True
                return False
        if not rows:
            return False
        transient, pdb_json, probe_json = rows[0]
        if transient:
            return False
        try:
            pdb_identities = json.loads(pdb_json or "[]")
            probe_identities = json.loads(probe_json or "[]")
        except ValueError:
            return False
        return (all(self._identity_matches(item) for item in pdb_identities)
                and all(self._identity_matches(item) for item in probe_identities))

    def symbol_meta(self, run_key: str) -> tuple[dict[str, str], str]:
        rows = self.connection.execute(
            f"SELECT evidence, stderr FROM {CACHE_ALIAS}.symbol_runs WHERE run_key = ?",
            [run_key]).fetchall()
        if not rows:
            return {}, ""
        row = rows[0]
        try:
            evidence = json.loads(row[0] or "{}")
        except ValueError:
            evidence = {}
        return evidence, str(row[1] or "")

    def range_meta(self, run_key: str) -> tuple[dict[str, Any], str]:
        rows = self.connection.execute(
            f"SELECT info, stderr FROM {CACHE_ALIAS}.range_runs WHERE run_key = ?",
            [run_key]).fetchall()
        if not rows:
            return {}, ""
        row = rows[0]
        try:
            info = json.loads(row[0] or "{}")
        except ValueError:
            info = {}
        return info, str(row[1] or "")

    # ------------------------------------------------------------------ stores

    @staticmethod
    def _redact(text: str) -> str:
        """Drop credentials from symbol-server URLs before persisting/replaying evidence."""
        return _CREDENTIALS.sub(r"\1***@", text)

    def _over_cap(self) -> bool:
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        if size > MAX_BYTES:
            self._warn(f"cache is {size} bytes (cap {MAX_BYTES}); not storing this run")
            return True
        return False

    def store_symbols(self, run_key: str, symbols: Path | None, publics: Path | None,
                      pdbs: Path | None, evidence: dict[str, str], stderr: str,
                      transient: bool, pdb_identity: list[dict[str, object]],
                      probe_identity: list[dict[str, object]]) -> None:
        if not self.ensure_write() or self._over_cap():
            return
        created = time.strftime("%Y-%m-%dT%H:%M:%S")
        clean_stderr = self._redact(stderr)
        try:
            self.connection.execute("BEGIN TRANSACTION")
            for table in ("symbols", "publics", "pdbs"):
                self.connection.execute(
                    f"DELETE FROM {CACHE_ALIAS}.{table} WHERE run_key = ?", [run_key])
            self.connection.execute(
                f"INSERT OR REPLACE INTO {CACHE_ALIAS}.symbol_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
                [run_key, created, json.dumps(evidence, sort_keys=True), clean_stderr,
                 int(bool(transient)), json.dumps(pdb_identity, sort_keys=True),
                 json.dumps(probe_identity, sort_keys=True)])
            if symbols is not None:
                self.connection.execute(
                    f"INSERT INTO {CACHE_ALIAS}.symbols "
                    "SELECT ?, module_name, address, function, function_short, "
                    "containing_function, CAST(file AS VARCHAR), "
                    "CAST(line AS INTEGER) FROM read_parquet(?)", [run_key, str(symbols)])
            if publics is not None:
                self.connection.execute(
                    f"INSERT INTO {CACHE_ALIAS}.publics "
                    "SELECT ?, module_name, CAST(rva AS VARCHAR), "
                    "CAST(name_count AS INTEGER), names FROM read_csv("
                    "?, header = true, all_varchar = true)", [run_key, str(publics)])
            if pdbs is not None:
                self.connection.execute(
                    f"INSERT INTO {CACHE_ALIAS}.pdbs "
                    "SELECT ?, module_name, pdb FROM read_csv("
                    "?, header = true, all_varchar = true)", [run_key, str(pdbs)])
            self.connection.execute("COMMIT")
        except Exception as exc:  # noqa: BLE001 - a cache write cannot fail the profile
            with contextlib.suppress(Exception):
                self.connection.execute("ROLLBACK")
            self._warn(f"symbol store failed ({exc}); the next run will re-derive")
            self.disabled = True

    def store_ranges(self, run_key: str, functions: Path | None, info: dict[str, Any],
                     stderr: str) -> None:
        if functions is None:
            return
        if not self.ensure_write() or self._over_cap():
            return
        created = time.strftime("%Y-%m-%dT%H:%M:%S")
        clean_stderr = self._redact(stderr)
        try:
            self.connection.execute("BEGIN TRANSACTION")
            self.connection.execute(
                f"DELETE FROM {CACHE_ALIAS}.range_runs WHERE run_key = ?", [run_key])
            self.connection.execute(
                f"DELETE FROM {CACHE_ALIAS}.ranges WHERE run_key = ?", [run_key])
            self.connection.execute(
                f"INSERT OR REPLACE INTO {CACHE_ALIAS}.range_runs VALUES (?, ?, ?, ?)",
                [run_key, created, json.dumps(info, sort_keys=True), clean_stderr])
            self.connection.execute(
                f"INSERT INTO {CACHE_ALIAS}.ranges "
                "SELECT ?, module_name, CAST(function_start AS VARCHAR), "
                "CAST(function_end AS VARCHAR), function_source, function_name "
                "FROM read_csv(?, header = true, all_varchar = true)",
                [run_key, str(functions)])
            self.connection.execute("COMMIT")
        except Exception as exc:  # noqa: BLE001
            with contextlib.suppress(Exception):
                self.connection.execute("ROLLBACK")
            self._warn(f"range store failed ({exc}); the next run will re-derive")
            self.disabled = True

    # -------------------------------------------------------------------- views

    def create_symbol_views(self, run_key: str) -> None:
        self.connection.execute("SET VARIABLE uprof_cache_symbols_key = ?", [run_key])
        views = (
            ("uprof_symbols_source", "symbols",
             "SELECT module_name, address, function, function_short, containing_function, "
             "file, line"),
            ("uprof_aliases_source", "publics",
             "SELECT module_name, rva, CAST(name_count AS INTEGER) AS name_count, names"),
            ("uprof_pdbs_source", "pdbs", "SELECT module_name, pdb"),
        )
        for view, table, select in views:
            self.connection.execute(
                f"CREATE OR REPLACE TEMP VIEW {view} AS {select} "
                f"FROM {CACHE_ALIAS}.{table} "
                "WHERE run_key = getvariable('uprof_cache_symbols_key')")

    def create_range_view(self, run_key: str) -> None:
        self.connection.execute("SET VARIABLE uprof_cache_ranges_key = ?", [run_key])
        self.connection.execute(f"""
            CREATE OR REPLACE TEMP VIEW uprof_functions_source AS
            SELECT module_name, function_start, function_end, function_source, function_name
            FROM {CACHE_ALIAS}.ranges
            WHERE run_key = getvariable('uprof_cache_ranges_key');
        """)
