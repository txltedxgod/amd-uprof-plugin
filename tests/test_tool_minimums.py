"""External tools below their minimum version stop the command that needs them.

AMD uProf must be 5.3 or later and every LLVM tool 23 or later. `tools` prints each found
version against its minimum; collect/translate (uProf) and a profile that symbolizes or
disassembles (LLVM) stop before any work with one cause line and runnable alternatives.
The versions CI pins must meet the same minimums.
Run from the repository root: python tests/run_tests.py test_tool_minimums
"""

import argparse
import contextlib
import io
import re
import types
import unittest
from pathlib import Path
from unittest import mock

import uprof_native
from uprof_util import UprofError

ROOT = Path(__file__).resolve().parents[1]
LLVM_BIN = Path("/llvm/bin")
UPROF = Path("/uprof/AMDuProfCLI")


@contextlib.contextmanager
def toolchain(llvm: dict[str, str | None], uprof: str | None = "AMDuProfCLI.exe Version 5.3.521.0"):
    """Every named LLVM tool is found with the given --version line; uProf likewise."""
    def version_line(path, *args):
        return llvm.get(Path(path).name)

    with mock.patch.object(uprof_native, "find_uprof", return_value=UPROF), \
            mock.patch.object(uprof_native, "_uprof_version", return_value=uprof), \
            mock.patch.object(uprof_native, "find_symbolizer",
                              return_value=(LLVM_BIN / "llvm-symbolizer"
                                            if "llvm-symbolizer" in llvm else None)), \
            mock.patch.object(uprof_native, "find_sibling",
                              side_effect=lambda symbolizer, name:
                              LLVM_BIN / name if name in llvm else None), \
            mock.patch.object(uprof_native, "_first_version_line", side_effect=version_line):
        yield


LLVM23 = "LLVM version 23.1.4"
LLVM22 = "LLVM version 22.1.8"
ALL23 = {name: LLVM23 for name in ("llvm-symbolizer", "llvm-readobj", "llvm-pdbutil", "llvm-objdump")}


class UprofMinimumTest(unittest.TestCase):
    def test_uprof_5_3_is_accepted(self):
        with toolchain({}):
            self.assertEqual(uprof_native.require_uprof(), UPROF)

    def test_uprof_below_5_3_stops_with_the_cause_and_alternatives(self):
        with toolchain({}, uprof="AMDuProfCLI.exe Version 5.2.606.0"):
            with self.assertRaises(UprofError) as caught:
                uprof_native.require_uprof()
        message = str(caught.exception)
        self.assertNotIn("\n", message)
        for part in ("5.2.606.0", "minimum 5.3", "AMDUPROF_CLI", "re-run"):
            self.assertIn(part, message)

    def test_an_unreadable_uprof_version_stops(self):
        with toolchain({}, uprof=None):
            with self.assertRaises(UprofError) as caught:
                uprof_native.require_uprof()
        self.assertIn("cannot read the version", str(caught.exception))


class LlvmMinimumTest(unittest.TestCase):
    def test_llvm_23_is_accepted(self):
        with toolchain(ALL23):
            self.assertEqual(uprof_native.require_symbolizer(), LLVM_BIN / "llvm-symbolizer")

    def test_a_symbolizer_below_23_stops_with_the_cause_and_alternatives(self):
        with toolchain(dict(ALL23, **{"llvm-symbolizer": LLVM22})):
            with self.assertRaises(UprofError) as caught:
                uprof_native.require_symbolizer()
        message = str(caught.exception)
        self.assertNotIn("\n", message)
        for part in ("22.1.8", "minimum 23", "LLVM_SYMBOLIZER", "re-run"):
            self.assertIn(part, message)

    def test_an_unreadable_llvm_version_stops(self):
        with toolchain(dict(ALL23, **{"llvm-symbolizer": None})):
            with self.assertRaises(UprofError) as caught:
                uprof_native.require_symbolizer()
        self.assertIn("cannot read the version", str(caught.exception))


class ProfileGateTest(unittest.TestCase):
    def setUp(self):
        try:
            import uprof_query
        except ImportError as exc:
            self.skipTest(f"uprof_query cannot be imported: {exc}")
        self.query = uprof_query

    def gate(self, by, json=False, function=None):
        self.query._require_llvm(argparse.Namespace(by=by, json=json, function=function))

    def test_instruction_context_stops_on_an_old_objdump_instead_of_omitting_every_row(self):
        with toolchain(dict(ALL23, **{"llvm-objdump": LLVM22})):
            with self.assertRaises(UprofError) as caught:
                self.gate("instruction", json=True)
        self.assertIn("llvm-objdump", str(caught.exception))

    def test_a_symbolizing_profile_stops_on_an_old_symbolizer(self):
        with toolchain(dict(ALL23, **{"llvm-symbolizer": LLVM22})):
            for by in ("function", "region", "line", "instruction"):
                with self.subTest(by=by), self.assertRaises(UprofError):
                    self.gate(by)

    def test_a_profile_without_llvm_work_does_not_check(self):
        with toolchain(dict(ALL23, **{"llvm-symbolizer": LLVM22})):
            for by in ("process", "module"):
                with self.subTest(by=by):
                    self.gate(by)

    def test_a_current_toolchain_passes(self):
        with toolchain(ALL23):
            self.gate("instruction", json=True)


class ToolsReportMinimumTest(unittest.TestCase):
    def report(self, llvm, uprof="AMDuProfCLI.exe Version 5.3.521.0"):
        out = io.StringIO()
        with toolchain(llvm, uprof), \
                mock.patch.dict("sys.modules", duckdb=types.SimpleNamespace(__version__="2.0.0")), \
                contextlib.redirect_stdout(out):
            try:
                uprof_native.tool_report()
                error = None
            except UprofError as exc:
                error = str(exc)
        return out.getvalue().splitlines(), error

    def test_each_found_tool_prints_its_minimum(self):
        rows, error = self.report(ALL23)
        self.assertIsNone(error)
        self.assertIn(f"UPROF={UPROF}; version=AMDuProfCLI.exe Version 5.3.521.0; minimum=5.3; ok",
                      rows)
        self.assertIn(f"OBJDUMP={LLVM_BIN / 'llvm-objdump'}; version={LLVM23}; minimum=23; ok", rows)

    def test_a_tool_below_its_minimum_prints_too_old_and_fails(self):
        rows, error = self.report(dict(ALL23, **{"llvm-objdump": LLVM22}))
        row = next(row for row in rows if row.startswith("OBJDUMP="))
        self.assertIn(f"version={LLVM22}; minimum=23; TOO OLD: ", row)
        self.assertIn("llvm-objdump", error)


class CiPinsTest(unittest.TestCase):
    def test_the_pinned_llvm_releases_meet_the_minimum(self):
        pins = []
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            pins += [(workflow.name, found) for found
                     in re.findall(r"LLVM_VERSION:\s*'([\d.]+)'|LLVM-([\d.]+)-win64\.msi", text)]
        versions = [(name, next(part for part in found if part)) for name, found in pins]
        self.assertTrue(versions)
        for name, version in versions:
            with self.subTest(workflow=name, version=version):
                self.assertGreaterEqual(uprof_native.parse_version(version),
                                        uprof_native.LLVM_MINIMUM)

    def test_the_reference_uprof_meets_the_minimum(self):
        text = (ROOT / "plugin" / "skills" / "amd-uprof" / "references" / "validation.md"
                ).read_text(encoding="utf-8")
        version = re.search(r"uProf CLI ([\d.]+\d)", text).group(1)
        self.assertGreaterEqual(uprof_native.parse_version(version), uprof_native.UPROF_MINIMUM)


if __name__ == "__main__":
    unittest.main()
