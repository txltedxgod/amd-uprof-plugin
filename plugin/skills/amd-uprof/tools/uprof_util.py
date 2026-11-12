"""Shared primitives: the CLI error type, stream setup, session copies."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Final

DUMP_FILENAMES: Final = MappingProxyType({
    "ibsop-event-dump": "IbsOpDump.csv",
    "ibsfetch-event-dump": "IbsFetchDump.csv",
})

COPY_DIRS: Final = ("cpu", "metadata", ".config", ".log", "sources", "binaries")

# Used when the skill is copied loose and no .claude-plugin/plugin.json sits above it. Keep it in
# step with the released plugin version.
_BUILTIN_VERSION: Final = "2.1.0"
_PLUGIN_MANIFEST: Final = Path(".claude-plugin") / "plugin.json"


class UprofError(RuntimeError):
    """A failure the CLI prints as `error: ...` and exits 2 for."""


def skill_identity(skill_dir: Path | None = None) -> str:
    """Name the skill version and the installed copy that produced an output line.

    Two copies can share a version and still differ, so the skill directory is part of the value.
    The nearest plugin.json above the skill supplies the version; without one (a loose copy) the
    built-in version is reported.
    """
    root = (skill_dir or Path(__file__).resolve().parent.parent).resolve()
    for candidate in (root, *root.parents):
        manifest = candidate / _PLUGIN_MANIFEST
        if not manifest.is_file():
            continue
        try:
            version = json.loads(manifest.read_text(encoding="utf-8"))["version"]
        except (OSError, ValueError, KeyError, TypeError):
            break
        if isinstance(version, str) and version:
            return f"amd-uprof {version} (plugin.json {manifest}); skill dir {root}"
        break
    return f"amd-uprof {_BUILTIN_VERSION} (built-in); skill dir {root}"


_TIME_FILTER = re.compile(r"(\d+(?:\.\d+)?):(\d+(?:\.\d+)?)")


def parse_time_filter(value: str) -> tuple[Decimal, Decimal] | None:
    """Parse T1:T2 seconds into Decimal bounds; None when the text is not T1:T2."""
    match = _TIME_FILTER.fullmatch(value.strip())
    if not match:
        return None
    return Decimal(match.group(1)), Decimal(match.group(2))


def configure_streams() -> None:
    """Keep non-ASCII symbol names readable on a legacy console code page."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def absolute(path: os.PathLike[str] | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def canonical(path: os.PathLike[str] | str) -> Path:
    """path absolute, with links, junctions and 8.3 names resolved and case folded where the
    platform folds case.

    Not unique: a UNC path, a mapped drive or a subst drive keeps its own spelling of a local
    directory, and missing trailing components keep theirs. Decide identity with same_path or
    contains, which also compare volume and file IDs.
    """
    full = absolute(path)
    try:
        full = Path(os.path.realpath(full))
    except (OSError, ValueError):
        pass
    return Path(os.path.normcase(os.fspath(full)))


def same_path(first: os.PathLike[str] | str, second: os.PathLike[str] | str) -> bool:
    """Whether both paths name the same file or directory, however each is spelled."""
    try:
        if os.path.samefile(first, second):
            return True
    except (OSError, ValueError):
        pass
    return canonical(first) == canonical(second)


def contains(outer: os.PathLike[str] | str, inner: os.PathLike[str] | str) -> bool:
    """Whether inner is outer or lies below it, however each is spelled.

    Every existing ancestor of inner is compared with outer by volume and file ID, which no
    spelling (UNC, mapped or subst drive, junction, 8.3 name) hides; the canonical string
    prefix covers an outer that does not exist yet.
    """
    if same_path(outer, inner):
        return True
    root, path = canonical(outer), canonical(inner)
    if root in path.parents:
        return True
    try:
        if not os.path.isdir(outer):
            return False
    except (OSError, ValueError):
        return False
    for ancestor in (absolute(inner), *absolute(inner).parents):
        try:
            if os.path.exists(ancestor) and os.path.samefile(outer, ancestor):
                return True
        except (OSError, ValueError):
            continue
    return False


def tail_lines(text: str, count: int = 6) -> str:
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    return " | ".join(lines[-count:])


def read_text(path: os.PathLike[str] | str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return handle.read()
    except OSError as exc:
        raise UprofError(f"cannot read {path}: {exc}") from exc


def copy_session(src: os.PathLike[str] | str, dst: os.PathLike[str] | str) -> None:
    """Copy session.uprof and the raw directories translate reads into dst.

    Existing files in dst are overwritten; callers that need a clean directory create one.
    Filesystem failures are reported with the path and a remedy, never as a traceback.
    """
    source = Path(src)
    target = Path(dst)
    if target.exists() and not target.is_dir():
        raise UprofError(f"output path exists and is not a directory: {target}; choose another "
                         "output directory")
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UprofError(f"cannot create output directory {target}: {exc}; choose another "
                         "output directory or fix its permissions") from exc
    try:
        shutil.copy2(source / "session.uprof", target / "session.uprof")
    except OSError as exc:
        raise UprofError(f"cannot copy {source / 'session.uprof'} to "
                         f"{target / 'session.uprof'}: {exc}; choose another output directory "
                         "or fix its permissions") from exc
    for name in COPY_DIRS:
        directory = source / name
        if directory.is_dir():
            try:
                shutil.copytree(directory, target / name, dirs_exist_ok=True)
            except OSError as exc:
                raise UprofError(f"cannot copy {directory} to {target / name}: {exc}; "
                                 "choose another output directory or fix its permissions") from exc


def require_dir(path: os.PathLike[str] | str, what: str) -> Path:
    full = absolute(path)
    if not full.is_dir():
        raise UprofError(
            f"{what} not found: {full} (pass the directory that holds session.uprof and cpu.db)")
    return full


def require_file(path: os.PathLike[str] | str, what: str, hint: str = "") -> Path:
    full = absolute(path)
    if not full.is_file():
        suffix = f"; {hint}" if hint else ""
        raise UprofError(f"{what} not found: {full}{suffix}")
    return full
