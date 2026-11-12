"""Export a translated timer capture of heap_churn.exe into this fixture directory.

Usage: python export_fixture.py <TRANSLATED_SESSION_DIR>

Writes session.uprof (only the keys the tools read, with host-specific values replaced) and
cpu_tables.json (the cpu.db tables profile reads, with host paths replaced). The DuckDB file
itself is not committed because its storage format is bound to the DuckDB version; the tests
rebuild cpu.db from cpu_tables.json with tests/timer_fixture.py.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
# Host paths of the captured image are replaced by this placeholder; tests pass the committed
# image with --image-path.
IMAGE_PLACEHOLDER = "c:\\fixture\\heap_churn.exe"
TABLES = ("Process", "ProcessThread", "Module", "ModuleInstance", "Function",
          "UnifiedSampleSeries")


def _scrub(value: object) -> object:
    if isinstance(value, str) and value.lower().endswith("heap_churn.exe"):
        return IMAGE_PLACEHOLDER
    return value


def _reduced_meta(meta: dict) -> dict:
    collection = meta.get("collection") or {}
    events = collection.get("events") or {}
    target = collection.get("target") or {}
    schedule = collection.get("schedule") or {}
    auxiliary = meta.get("auxiliary") or {}
    return {
        "collectCommand": "AMDuProfCLI.exe collect --config tbp -o <OUT_DIR> heap_churn.exe",
        "collection": {
            "events": {key: events.get(key) for key in (
                "configName", "ibsEvents", "pmcEvents", "timerInterval", "timerSamplingMode")},
            "schedule": {key: schedule.get(key) for key in (
                "elapsed", "start", "end", "startTs", "endTs", "profileDuration")},
            "target": {"systemWide": target.get("systemWide"),
                       "launchApp": "heap_churn.exe"},
        },
        "auxiliary": {"eventColumnIds": auxiliary.get("eventColumnIds"),
                      "ibsOpSampling": auxiliary.get("ibsOpSampling"),
                      "cores": auxiliary.get("cores")},
    }


def main(session: Path) -> None:
    meta = json.loads((session / "session.uprof").read_text(encoding="utf-8-sig"))
    (HERE / "session.uprof").write_text(json.dumps(_reduced_meta(meta), indent=1) + "\n",
                                        encoding="utf-8")
    connection = duckdb.connect(str(session / "cpu.db"), read_only=True)
    tables = {}
    try:
        for table in TABLES:
            described = connection.execute(f'DESCRIBE "{table}"').fetchall()
            rows = connection.execute(f'SELECT * FROM "{table}" ORDER BY ALL').fetchall()
            tables[table] = {
                "columns": [[name, kind] for name, kind, *_ in described],
                "rows": [[_scrub(value) for value in row] for row in rows],
            }
    finally:
        connection.close()
    text = json.dumps(tables, separators=(",", ":"))
    # One table per line keeps a recapture diff readable.
    text = re.sub(r'(?<=\]\]\}),(?=")', ",\n", text)
    (HERE / "cpu_tables.json").write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
