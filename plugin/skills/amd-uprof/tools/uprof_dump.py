"""Resolve the IBS ASCII dump time_share reads.

Preference: one beside the session, a current cached dump, then a dump generated on a copy of the
raw session under the temp directory. The source session is never translated in place. A dump-only
translate still writes a degraded cpu.db, so every database is removed from the cache before it is
handed back.

Generation runs in a unique staging directory renamed into place when complete, so concurrent
runs cannot delete each other's work. The Linux branch is kept but unverified on this host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from uprof_native import TRANSLATE_TIMEOUT, failure, require_uprof, run, translate_command
from uprof_session import Sampler
from uprof_util import DUMP_FILENAMES, UprofError, absolute, copy_session, read_text, tail_lines

_TIME_FILTER = re.compile(r"--time-filter[ =]+(\d+(?:\.\d+)?:\d+(?:\.\d+)?)")

# The dump columns time_share reads. A run may hand views.sql a Parquet copy of exactly these
# columns instead of the ASCII dump; see samples_parquet().
SAMPLE_COLUMNS: Final = ("DeltaTick", "CPU_Number", "TID", "PID", "Offset", "ModuleName",
                         "IbsTagToRetCtr")
# Bump when SAMPLE_COLUMNS or the conversion below changes; it invalidates every samples cache.
_SAMPLES_FORMAT: Final = 1


@dataclass
class DumpInfo:
    """A resolved dump, its provenance, and the cache it may live in.

    source is beside | reused | generated; reason is printed with the DUMP line; time_filter is the
    translate window recorded for the dump.
    """

    path: Path
    source: str
    cache_dir: Path | None = None
    reason: str = ""
    time_filter: str | None = None


def cache_dir(session_dir: Path | str) -> Path:
    full = os.path.normcase(os.path.abspath(os.fspath(session_dir))).rstrip("\\/")
    digest = hashlib.sha256(full.encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / "uprof-dump-cache" / digest


def _samples_paths(dump_path: Path, directory: Path) -> tuple[Path, Path]:
    name = Path(dump_path).stem + ".samples.parquet"
    return directory / name, directory / (name + ".json")


def _unsupported_path(target: Path) -> Path:
    return target.with_name(target.name + ".unsupported.json")


def _file_key(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def _sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _read_samples_meta(path: Path) -> dict[str, object] | None:
    try:
        meta = json.loads(read_text(path))
    except (UprofError, ValueError):
        return None
    return meta if isinstance(meta, dict) else None


def _normalized_source(source: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(source)))


def _copy_valid(target: Path, meta: dict[str, object]) -> bool:
    """The copy itself still matches the size and digest recorded when it was written."""
    try:
        if not target.is_file() or target.stat().st_size != meta.get("copy_bytes"):
            return False
        return _sha256_file(target) == meta.get("copy_sha256")
    except OSError:
        return False


def _samples_meta_matches(meta: dict[str, object] | None, source: Path,
                          key: tuple[int, int], target: Path) -> bool:
    return bool(meta
                and meta.get("format") == _SAMPLES_FORMAT
                and meta.get("columns") == list(SAMPLE_COLUMNS)
                and meta.get("source") == _normalized_source(source)
                and meta.get("bytes") == key[0]
                and meta.get("mtime_ns") == key[1]
                and _copy_valid(target, meta))


def _write_samples_meta(path: Path, meta: dict[str, object]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(meta, handle, indent=2)


def _read_unsupported(path: Path) -> dict[str, object] | None:
    try:
        marker = json.loads(read_text(path))
    except (UprofError, ValueError):
        return None
    return marker if isinstance(marker, dict) else None


def _unsupported_marker_matches(marker: dict[str, object] | None, source: Path,
                                key: tuple[int, int]) -> bool:
    """A previous build proved this source lacks a required column; skip it until it changes."""
    return bool(marker
                and marker.get("format") == _SAMPLES_FORMAT
                and marker.get("columns") == list(SAMPLE_COLUMNS)
                and marker.get("source") == _normalized_source(source)
                and marker.get("bytes") == key[0]
                and marker.get("mtime_ns") == key[1])


def _write_unsupported(path: Path, source: Path, key: tuple[int, int],
                       missing: list[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"format": _SAMPLES_FORMAT, "columns": list(SAMPLE_COLUMNS),
                   "source": _normalized_source(source), "bytes": key[0],
                   "mtime_ns": key[1], "missing": missing}, handle, indent=2)


def samples_parquet_files(dump: DumpInfo, session_dir: Path | str) -> tuple[Path, ...]:
    """The files samples_parquet reads or writes for this dump: copy, sidecar, unsupported marker."""
    target, meta_path = _samples_paths(Path(dump.path), _samples_dir(dump, session_dir))
    return target, meta_path, _unsupported_path(target)


def _samples_dir(dump: DumpInfo, session_dir: Path | str) -> Path:
    return dump.cache_dir if dump.cache_dir is not None else cache_dir(session_dir)


def samples_parquet(dump: DumpInfo, session_dir: Path | str) -> Path | None:
    """A Parquet copy of the dump's SAMPLE_COLUMNS, built or refreshed on demand.

    The sidecar records the source size, mtime and sha256 and the copy's size and sha256. A
    matching source size and mtime reuse the copy after verifying the copy's recorded size and
    digest; a source mismatch compares the source sha256, so rewritten bytes reuse the copy and a
    changed dump rebuilds it. Any failure returns None, and the caller reads the CSV. A dump that
    lacks a required column is recorded, so later runs skip the rebuild and the source hash until
    it changes.
    """
    source = Path(dump.path)
    key = _file_key(source)
    if key is None:
        return None
    directory = _samples_dir(dump, session_dir)
    target, meta_path, unsupported_path = samples_parquet_files(dump, session_dir)
    if _unsupported_marker_matches(_read_unsupported(unsupported_path), source, key):
        return None
    meta = _read_samples_meta(meta_path)
    if target.is_file() and _samples_meta_matches(meta, source, key, target):
        return target
    sha = _sha256_file(source)
    if sha is None:
        return None
    if (target.is_file() and meta is not None and meta.get("sha256") == sha
            and meta.get("format") == _SAMPLES_FORMAT
            and meta.get("columns") == list(SAMPLE_COLUMNS)
            and _copy_valid(target, meta)):
        try:
            _write_samples_meta(meta_path, {**meta, "source": _normalized_source(source),
                                            "bytes": key[0], "mtime_ns": key[1]})
        except OSError:
            return None
        return target
    built = _build_samples(source, target, meta_path, unsupported_path, directory, sha, key)
    if built is None:
        print(f"WARNING: cannot build the Parquet dump copy for {source}; reading the CSV",
              file=sys.stderr)
        return None
    try:
        unsupported_path.unlink()
    except OSError:
        pass
    return built


def _build_samples(source: Path, target: Path, meta_path: Path, unsupported_path: Path,
                   directory: Path, sha: str, key: tuple[int, int]) -> Path | None:
    try:
        import duckdb
    except ImportError:
        return None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handle, staging_name = tempfile.mkstemp(prefix=f".{target.stem}-",
                                                suffix=".parquet.tmp", dir=directory)
        os.close(handle)
    except OSError:
        return None
    staging = Path(staging_name)
    try:
        connection = None
        try:
            connection = duckdb.connect()
            # The CSV order is the tie-break for lag() over equal DeltaTick values; keep it.
            connection.execute("SET preserve_insertion_order = true")
            columns = ", ".join(f'"{name}"' for name in SAMPLE_COLUMNS)
            connection.execute(
                f"COPY (SELECT {columns} FROM read_csv(?, header = true, all_varchar = true)) "
                "TO ? (FORMAT PARQUET, COMPRESSION zstd)", [str(source), str(staging)])
            rows = connection.execute("SELECT count(*) FROM read_parquet(?)",
                                      [str(staging)]).fetchone()[0]
        except (duckdb.Error, OSError) as exc:
            # A dump without one of SAMPLE_COLUMNS (a fetch dump has no tag column) can never
            # build this copy; record that so later runs skip the rebuild and the source hash.
            missing: list[str] = []
            if isinstance(exc, duckdb.Error) and connection is not None:
                try:
                    described = connection.execute(
                        "DESCRIBE SELECT * FROM read_csv(?, header = true, all_varchar = true)",
                        [str(source)]).fetchall()
                    available = {str(row[0]) for row in described}
                    missing = [name for name in SAMPLE_COLUMNS if name not in available]
                except duckdb.Error:
                    missing = []
            if missing:
                try:
                    _write_unsupported(unsupported_path, source, key, missing)
                except OSError:
                    pass
            return None
        finally:
            if connection is not None:
                connection.close()
        try:
            os.replace(staging, target)
            copy_sha = _sha256_file(target)
            if copy_sha is None:
                raise OSError("cannot read back the Parquet copy")
            _write_samples_meta(meta_path, {
                "format": _SAMPLES_FORMAT, "source": _normalized_source(source),
                "bytes": key[0], "mtime_ns": key[1], "sha256": sha, "rows": int(rows),
                "columns": list(SAMPLE_COLUMNS), "copy_bytes": target.stat().st_size,
                "copy_sha256": copy_sha})
        except (OSError, ValueError):
            return None
        return target
    finally:
        staging.unlink(missing_ok=True)


def remove_databases(directory: Path) -> None:
    if not directory.is_dir():
        return
    for path in directory.rglob("*"):
        if path.is_file() and re.search(r"\.(db|duckdb)(\.(wal|shm))?$", path.name, re.IGNORECASE):
            try:
                path.unlink()
            except OSError as exc:
                print(f"WARNING: could not remove {path}: {exc}; the cache copy still contains "
                      "a database", file=sys.stderr)


def newest_raw_prd(session_dir: Path | str) -> float | None:
    cpu_dir = Path(session_dir) / "cpu"
    if not cpu_dir.is_dir():
        return None
    times = [path.stat().st_mtime
             for path in cpu_dir.iterdir() if path.name.lower().endswith(".prd")]
    return max(times) if times else None


def recorded_time_filter(session_dir: Path | str) -> str | None:
    """The T1:T2 window of the session's recorded translate --time-filter, or None.

    A resolved dump may have been produced by that translate, so it may hold only the window's
    samples rather than the whole capture.
    """
    try:
        meta = json.loads(read_text(Path(session_dir) / "session.uprof"))
    except (UprofError, json.JSONDecodeError):
        return None
    match = _TIME_FILTER.search(str(meta.get("translateCommand") or ""))
    return match.group(1) if match else None


def _write_cache_meta(path: Path, session_dir: Path | str, kind: str, time_filter: str | None,
                      dump: Path) -> None:
    meta = {"sessionPath": str(session_dir), "kind": kind, "timeFilter": time_filter or "",
            "dump": str(dump)}
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(meta, handle, indent=2)
    except OSError as exc:
        raise UprofError(f"cannot write {path}: {exc}; check free space and permissions on the "
                         "dump cache") from exc


def _make_dump(session_dir: Path | str, kind: str, time_filter: str | None, cache: Path) -> Path:
    dump_name = DUMP_FILENAMES[kind]
    final_dump = cache / dump_name
    uprof = require_uprof()
    print(f"GENERATING DUMP: {cache} (AMDuProfCLI translate --ascii; this can take hours)",
          file=sys.stderr)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UprofError(f"cannot create the dump cache {cache.parent}: {exc}; free the path or "
                         "fix its permissions") from exc
    try:
        staging = Path(tempfile.mkdtemp(prefix="uprof-dump-", dir=cache.parent))
    except OSError as exc:
        raise UprofError(f"cannot create a staging directory in {cache.parent}: {exc}; check "
                         "free space and permissions on the temp directory") from exc
    try:
        copy_session(session_dir, staging)
        command = translate_command(uprof, staging, time_filter=time_filter, ascii_kind=kind)
        completed = run(command, timeout=TRANSLATE_TIMEOUT)
        detail = tail_lines((completed.stdout or "") + "\n" + (completed.stderr or ""))
        if completed.returncode != 0:
            raise UprofError(f"AMDuProfCLI translate --ascii {kind} failed with "
                             f"{completed.returncode} on the cache copy {staging}: {detail}")
        dump = staging / dump_name
        if not dump.is_file():
            raise UprofError(f"translate --ascii did not produce {dump_name} in {staging}; "
                             f"output: {detail}")
        try:
            size = dump.stat().st_size
        except OSError as exc:
            raise UprofError(f"cannot read {dump}: {exc}; the dump may have been removed during "
                             "translation") from exc
        if size <= 0:
            raise UprofError(f"translate --ascii produced an empty {dump_name} in {staging}; "
                             f"output: {detail}")
        remove_databases(staging)
        _write_cache_meta(staging / "cache.json", session_dir, kind, time_filter, final_dump)
        try:
            if cache.is_dir():
                shutil.rmtree(cache)
            os.replace(staging, cache)
        except OSError as exc:
            # Another run may have installed a complete cache first; keep it only when it
            # matches this request, never as a fallback for a stale dump.
            try:
                meta = json.loads(read_text(cache / "cache.json"))
            except (UprofError, json.JSONDecodeError):
                meta = {}
            current = (final_dump.is_file() and str(meta.get("kind")) == kind
                       and str(meta.get("timeFilter") or "") == str(time_filter or ""))
            if not current:
                raise UprofError(f"cannot install the dump cache at {cache}: {exc}; remove the "
                                 "path or fix its permissions and retry") from exc
            shutil.rmtree(staging, ignore_errors=True)
        return final_dump
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def resolve_dump(session_dir: Path | str, sampler: Sampler) -> DumpInfo:
    meta_path = Path(session_dir) / "session.uprof"
    if not meta_path.is_file():
        raise UprofError(
            f"session.uprof is missing from {session_dir}; time_share needs it to identify the "
            "sampler and check the dump against the capture span")
    if not sampler.ibs_dump_kind:
        raise failure("session.uprof records no IBS, PMC or timer event",
                      ["timer capture", "timer capture (launch)", "Zen host"])
    dump_name = DUMP_FILENAMES[sampler.ibs_dump_kind]
    path = Path(session_dir) / dump_name
    if path.is_file():
        return DumpInfo(absolute(path), "beside", reason="found beside the session")

    time_filter = recorded_time_filter(session_dir)
    cache = cache_dir(session_dir)
    cached_dump = cache / dump_name
    cache_meta = cache / "cache.json"
    newest_raw = newest_raw_prd(session_dir)

    reuse = False
    reason = "no cached dump for this session"
    if cache_meta.is_file():
        try:
            meta = json.loads(read_text(cache_meta))
        except (UprofError, json.JSONDecodeError):
            meta = None
        if not meta or not cached_dump.is_file():
            reason = "cached dump or its metadata is missing"
        elif str(meta.get("kind")) != sampler.ibs_dump_kind:
            reason = f"cached dump is for {meta.get('kind')}, not {sampler.ibs_dump_kind}"
        elif str(meta.get("timeFilter") or "") != str(time_filter or ""):
            reason = "cached dump was made with a different time filter"
        elif newest_raw and cached_dump.stat().st_mtime < newest_raw:
            reason = "cached dump is older than the session's raw cpu/*.prd"
        else:
            reuse = True
    if reuse:
        remove_databases(cache)
        return DumpInfo(absolute(cached_dump), "reused", cache_dir=cache,
                        reason="dump is at least as new as the session's raw cpu/*.prd",
                        time_filter=time_filter)

    dump = _make_dump(session_dir, sampler.ibs_dump_kind, time_filter, cache)
    return DumpInfo(absolute(dump), "generated", cache_dir=cache, reason=reason,
                    time_filter=time_filter)
