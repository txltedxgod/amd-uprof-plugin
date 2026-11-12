"""--out-file must never name a file the command reads or derives from its inputs."""

import contextlib
import os
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

import debug_fixtures as F
from test_translate_out_dir import _short_path

_OVERWRITE = "--out-file would overwrite"
_REMEDY = "choose a different --out-file path"


class _Reached(Exception):
    """The command got past every guard."""


@unittest.skipIf(F.duckdb_skip(), F.duckdb_skip())
class OutFileGuardTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="uprof-outguard-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(os.path.realpath(self._tmp.name))
        self.session = self.root / "session"
        self.session.mkdir()
        (self.session / "session.uprof").write_text(
            '{"collection": {"target": {"systemWide": true}}, "translateCommand": ""}',
            encoding="utf-8")
        import duckdb
        connection = duckdb.connect(str(self.session / "cpu.db"))
        self.image = self.root / "app.exe"
        self.image.write_bytes(b"image")
        connection.execute("CREATE TABLE Module (path VARCHAR)")
        connection.execute("INSERT INTO Module VALUES (?)", [str(self.image)])
        connection.close()
        self.dump = self.root / "IbsOpDump.csv"
        self.dump.write_text("DeltaTick\n1\n", encoding="utf-8")
        self.cache = self.root / "dump-cache"
        self.cache.mkdir()

    def _run(self, *extra):
        args = uprof.build_parser().parse_args(
            ["profile", "--session", str(self.session), "--by", "process", "--top", "5",
             *extra])

        @contextlib.contextmanager
        def real_connection(cpu_db, view_files, variables, views=None):
            import duckdb
            connection = duckdb.connect(str(cpu_db), read_only=True)
            try:
                yield connection
            finally:
                connection.close()

        def parquet(dump, session_dir):
            target = Path(dump.cache_dir) / (Path(dump.path).stem + ".samples.parquet")
            target.write_bytes(b"rebuilt")
            return target

        sampler = types.SimpleNamespace(pmc=False, event_column="")
        dump = uprof_dump.DumpInfo(self.dump, "beside", self.cache)
        with mock.patch.object(uprof_session, "derive_sampler", return_value=sampler), \
                mock.patch.object(uprof_session, "system_wide", return_value=True), \
                mock.patch.object(uprof_dump, "resolve_dump", return_value=dump), \
                mock.patch.object(uprof_dump, "samples_parquet", side_effect=parquet), \
                mock.patch.object(uprof_dump, "recorded_time_filter", return_value=None), \
                mock.patch.object(uprof_query, "_primary_measure",
                                  return_value=("sample_share", None)), \
                mock.patch.object(uprof_query, "_dump_sanity", side_effect=_Reached()), \
                mock.patch.object(uprof_query.uprof_db, "open_query", real_connection):
            uprof_query.run_query_command(args)

    def _assert_refused(self, target, *extra, out_file=None):
        before = target.read_bytes()
        with self.assertRaisesRegex(uprof_util.UprofError, _OVERWRITE) as raised:
            self._run(*extra, "--out-file", str(target) if out_file is None else out_file)
        self.assertIn(_REMEDY, str(raised.exception))
        self.assertEqual(target.read_bytes(), before)

    def test_the_capture_database_refusal_names_the_remedy(self):
        self._assert_refused(self.session / "cpu.db")

    def test_relative_paths_are_compared_as_absolute_paths(self):
        pdb = self.root / "app.pdb"
        pdb.write_bytes(b"pdb")
        cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, cwd)
        self._assert_refused(pdb, "--symbol-path", "app.pdb",
                             out_file=os.path.join("session", "..", "app.pdb"))

    @unittest.skipUnless(os.name == "nt", "host: case-insensitive paths need Windows")
    def test_a_differently_cased_path_is_the_same_file_on_windows(self):
        pdb = self.root / "app.pdb"
        pdb.write_bytes(b"pdb")
        self._assert_refused(pdb, "--symbol-path", str(pdb), out_file=str(pdb).upper())

    def test_an_explicit_symbol_file_is_protected(self):
        pdb = self.root / "app.pdb"
        pdb.write_bytes(b"pdb")
        self._assert_refused(pdb, "--symbol-path", str(pdb))

    def test_an_explicit_image_file_is_protected(self):
        image = self.root / "other.exe"
        image.write_bytes(b"other")
        self._assert_refused(image, "--image-path", str(image))

    def test_the_captured_module_image_is_protected(self):
        self._assert_refused(self.image)

    def test_a_module_image_found_in_an_image_directory_is_protected(self):
        images = self.root / "images"
        images.mkdir()
        found = images / "app.exe"
        found.write_bytes(b"found")
        self._assert_refused(found, "--image-path", str(images))

    def test_the_parquet_dump_copy_is_protected(self):
        copy = self.cache / "IbsOpDump.samples.parquet"
        copy.write_bytes(b"copy")
        self._assert_refused(copy)

    def test_the_parquet_copy_sidecar_is_protected(self):
        sidecar = self.cache / "IbsOpDump.samples.parquet.json"
        sidecar.write_text("{}", encoding="utf-8")
        self._assert_refused(sidecar)

    def _junction(self, target):
        if os.name != "nt":
            self.skipTest("host: junctions exist on Windows only")
        import _winapi
        link = self.root / "junction"
        _winapi.CreateJunction(str(target), str(link))
        return link

    def _unc(self, path):
        if os.name != "nt":
            self.skipTest("host: UNC paths exist on Windows only")
        drive, rest = os.path.splitdrive(str(path))
        share = Path(rf"\\localhost\{drive[0]}$" + "\\")
        if not share.is_dir():
            self.skipTest("host: the administrative share is not reachable")
        return rf"\\localhost\{drive[0]}$" + rest

    def test_the_capture_database_through_a_junction_is_protected(self):
        cpu_db = self.session / "cpu.db"
        self._assert_refused(cpu_db, out_file=str(self._junction(self.session) / "cpu.db"))

    def test_the_capture_database_through_a_symlink_is_protected(self):
        cpu_db = self.session / "cpu.db"
        link = self.root / "link.db"
        try:
            link.symlink_to(cpu_db)
        except OSError as exc:
            self.skipTest(f"host: cannot create a file symlink here: {exc}")
        self._assert_refused(cpu_db, out_file=str(link))

    def test_the_capture_database_through_its_short_name_is_protected(self):
        cpu_db = self.session / "cpu.db"
        short = _short_path(self.session)
        if short is None:
            self.skipTest("host: the volume keeps no 8.3 names")
        self._assert_refused(cpu_db, out_file=str(short / "cpu.db"))

    def test_the_capture_database_through_a_unc_path_is_protected(self):
        cpu_db = self.session / "cpu.db"
        self._assert_refused(cpu_db, out_file=self._unc(cpu_db))

    def test_a_hard_link_to_a_symbol_file_is_protected(self):
        pdb = self.root / "app.pdb"
        pdb.write_bytes(b"pdb")
        link = self.root / "other-name.pdb"
        try:
            os.link(pdb, link)
        except OSError as exc:
            self.skipTest(f"host: cannot create a hard link here: {exc}")
        self._assert_refused(pdb, "--symbol-path", str(pdb), out_file=str(link))

    def test_the_parquet_copy_through_a_junction_is_protected(self):
        copy = self.cache / "IbsOpDump.samples.parquet"
        copy.write_bytes(b"copy")
        link = self._junction(self.cache)
        self._assert_refused(copy, out_file=str(link / copy.name))

    def test_the_parquet_unsupported_marker_is_protected(self):
        marker = self.cache / "IbsOpDump.samples.parquet.unsupported.json"
        marker.write_text("{}", encoding="utf-8")
        self._assert_refused(marker)

    def test_an_unrelated_out_file_passes_every_guard(self):
        with self.assertRaises(_Reached):
            self._run("--out-file", str(self.root / "table.txt"))


if __name__ == "__main__":
    unittest.main()
