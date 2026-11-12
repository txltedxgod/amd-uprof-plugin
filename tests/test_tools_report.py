"""`tools` prints a row for every tool the commands run, llvm-objdump included.

Run from the repository root: python tests/run_tests.py test_tools_report
"""

import contextlib
import io
import types
import unittest
from pathlib import Path
from unittest import mock

import uprof_native

SYMBOLIZER = Path("/llvm/bin/llvm-symbolizer")


def report(siblings: dict[str, Path | None]) -> list[str]:
    """The `tools` rows with uProf, DuckDB and llvm-symbolizer present and siblings as given."""
    out = io.StringIO()
    with mock.patch.object(uprof_native, "find_uprof", return_value=Path("/uprof/AMDuProfCLI")), \
            mock.patch.object(uprof_native, "find_symbolizer", return_value=SYMBOLIZER), \
            mock.patch.object(uprof_native, "find_sibling",
                              side_effect=lambda symbolizer, name: siblings.get(name)), \
            mock.patch.object(uprof_native, "_first_version_line", return_value="LLVM version 23.1.4"), \
            mock.patch.object(uprof_native, "_uprof_version", return_value="AMDuProfCLI.exe Version 5.3.521.0"), \
            mock.patch.dict("sys.modules", duckdb=types.SimpleNamespace(__version__="2.0.0")), \
            contextlib.redirect_stdout(out):
        uprof_native.tool_report()
    return out.getvalue().splitlines()


class ToolsReportTest(unittest.TestCase):
    def test_a_found_objdump_prints_its_path_and_version(self):
        objdump = Path("/llvm/bin/llvm-objdump")
        rows = report({"llvm-objdump": objdump})
        self.assertIn(f"OBJDUMP={objdump}; version=LLVM version 23.1.4; minimum=23; ok", rows)

    def test_a_missing_objdump_prints_the_cause_and_remedy_without_failing(self):
        rows = report({})
        self.assertIn("OBJDUMP=; version=MISSING (llvm-objdump is not beside llvm-symbolizer or "
                      "on PATH; instruction context is omitted; remedy: install LLVM or add its "
                      "bin directory to PATH; module/RVA rows still work)", rows)


if __name__ == "__main__":
    unittest.main()
