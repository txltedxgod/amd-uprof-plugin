"""The profile command must hand the samples sidecar to views.sql."""

import contextlib
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import uprof
import uprof_dump
import uprof_query
import uprof_session
import uprof_util


class _Abort(Exception):
    pass


class ParquetWiringTest(unittest.TestCase):
    def test_the_command_sets_the_samples_variable_from_the_sidecar(self):
        with tempfile.TemporaryDirectory(prefix="uprof-wiring-") as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            (session / "session.uprof").write_text(
                '{"collection": {"target": {"systemWide": true}}, "translateCommand": ""}',
                encoding="utf-8")
            import duckdb
            duckdb.connect(str(session / "cpu.db")).close()
            dump_path = root / "IbsOpDump.csv"
            dump_path.write_text("DeltaTick\n1\n", encoding="utf-8")
            sidecar = root / "IbsOpDump.samples.parquet"
            sidecar.write_bytes(b"parquet")
            out = root / "out.txt"
            args = uprof.build_parser().parse_args(
                ["profile", "--session", str(session), "--by", "process",
                 "--top", "5", "--out-file", str(out)])
            captured = {}

            @contextlib.contextmanager
            def fake_open_query(cpu_db, view_files, variables, views=None):
                captured["variables"] = dict(variables)
                captured["views"] = views
                raise _Abort()
                yield

            sampler = types.SimpleNamespace(pmc=False, timer=False, event_column="")
            with mock.patch.object(uprof_query, "_check_args", return_value=None), \
                    mock.patch.object(uprof_session, "derive_sampler", return_value=sampler), \
                    mock.patch.object(uprof_session, "system_wide", return_value=True), \
                    mock.patch.object(uprof_dump, "resolve_dump",
                                      return_value=uprof_dump.DumpInfo(dump_path, "beside")), \
                    mock.patch.object(uprof_dump, "samples_parquet", return_value=sidecar), \
                    mock.patch.object(uprof_dump, "recorded_time_filter", return_value=None), \
                    mock.patch.object(uprof_query, "_primary_measure",
                                      return_value=("sample_share", None)), \
                    mock.patch.object(uprof_query.uprof_db, "open_query", fake_open_query):
                with self.assertRaises(_Abort):
                    uprof_query.run_query_command(args)

        self.assertEqual(captured["variables"]["uprof_ibs_parquet"], str(sidecar))


if __name__ == "__main__":
    unittest.main()
