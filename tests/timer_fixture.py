"""Build the committed timer capture (tests/fixtures/timer) as a session directory.

session.uprof is copied; cpu.db is rebuilt from cpu_tables.json, so no DuckDB file is committed.
The image heap_churn.exe and its PDB stay in the fixture directory; pass that directory with
--image-path, because Module.path holds a placeholder, not a path on this host.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "timer"
IMAGE_DIR = FIXTURE
EVENT_COLUMN = "event#0x200000000e000"
IMAGE_KEY = "c:/fixture/heap_churn.exe"
NTDLL_KEY = "c:/windows/system32/ntdll.dll"


def tables() -> dict:
    return json.loads((FIXTURE / "cpu_tables.json").read_text(encoding="utf-8"))


def meta() -> dict:
    return json.loads((FIXTURE / "session.uprof").read_text(encoding="utf-8"))


def build(session: Path, meta_override: dict | None = None,
          drop_columns: tuple[str, ...] = (), keep_rows: int | None = None) -> Path:
    """Write the fixture session into session (created); return it.

    meta_override replaces session.uprof; drop_columns leaves those UnifiedSampleSeries columns
    out of cpu.db; keep_rows keeps only that many UnifiedSampleSeries rows.
    """
    import duckdb

    session.mkdir(parents=True)
    if meta_override is None:
        shutil.copyfile(FIXTURE / "session.uprof", session / "session.uprof")
    else:
        (session / "session.uprof").write_text(json.dumps(meta_override), encoding="utf-8")
    connection = duckdb.connect(str(session / "cpu.db"))
    try:
        for name, table in tables().items():
            keep = [index for index, (column, _kind) in enumerate(table["columns"])
                    if not (name == "UnifiedSampleSeries" and column in drop_columns)]
            columns = ", ".join(f'"{table["columns"][i][0]}" {table["columns"][i][1]}'
                                for i in keep)
            connection.execute(f'CREATE TABLE "{name}" ({columns})')
            source = table["rows"]
            if name == "UnifiedSampleSeries" and keep_rows is not None:
                source = source[:keep_rows]
            rows = [[row[i] for i in keep] for row in source]
            if rows:
                marks = ", ".join("?" for _ in keep)
                connection.executemany(f'INSERT INTO "{name}" VALUES ({marks})', rows)
    finally:
        connection.close()
    return session
