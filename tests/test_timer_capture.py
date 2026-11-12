"""Timer-based captures (AMDuProfCLI collect --config tbp) are profiled as their own mode.

A timer capture records no IBS or PMC event; each sample is one timer tick that found a thread
running, so sample_share is an on-CPU time share. Unsupported cases fail with one cause line and
runnable ALTERNATIVE lines instead of switching mode (issue #190). The fixture is a real capture
of tests/fixtures/timer/heap_churn.exe; cpu.db is rebuilt from cpu_tables.json.

Run from the repository root: python tests/run_tests.py test_timer_capture
"""

import contextlib
import copy
import io
import json
import math
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import timer_fixture
import uprof_collect
import uprof_dump
import uprof_native
import uprof_session

TOOLS_DIR = Path(__file__).resolve().parents[1] / "plugin" / "skills" / "amd-uprof" / "tools"

METRIC = ("METRIC: timer sampling (CPU_TIME, interval 1 ms) -- sample shares: on-CPU time share "
          "of the sampled threads (one sample per timer tick that found the thread running; "
          "kernel-mode ticks not established), not cycles, not wall time; not available from a "
          "timer capture: time_share, tag_to_retire_share, cycle cost, per-op cost, caller "
          "attribution into external modules")
METRIC_WIDE = METRIC.replace(
    "kernel-mode ticks not established)",
    "kernel-mode ticks not established; system-wide denominator and idle handling unverified)")
FAKE_CLI = "/opt/uprof/bin/AMDuProfCLI"
TOTAL = 1446
IMAGE_SAMPLES = 1052
NTDLL_SAMPLES = 393
HASH_SAMPLES = 826
HASH_NAME = "static unsigned int hash_block(const unsigned char *, unsigned int)"


def _duckdb_missing():
    try:
        import duckdb  # noqa: F401
    except ImportError:
        return "duckdb is required; install duckdb==2.0.0"
    return None


def _symbolizer_skip():
    symbolizer = uprof_native.find_symbolizer()
    if symbolizer is None:
        return "llvm-symbolizer is required; install LLVM"
    return None


def _pdb_skip():
    symbolizer = uprof_native.find_symbolizer()
    if symbolizer is None:
        return "llvm-symbolizer is required; install LLVM"
    return uprof_native.pdb_option_cause(str(symbolizer))


def _alternatives(text):
    return [line for line in text.splitlines() if line.startswith("ALTERNATIVE: ")]


def _labels(text):
    return [line[len("ALTERNATIVE: "):].split(": ", 1)[0] for line in _alternatives(text)]


class _Session(unittest.TestCase):
    def setUp(self):
        reason = _duckdb_missing()
        if reason:
            self.skipTest(reason)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.session = timer_fixture.build(self.root / "timer")

    def run_tool(self, *args):
        return subprocess.run([sys.executable, str(TOOLS_DIR / "uprof.py"), *args],
                              capture_output=True, text=True, encoding="utf-8")

    def profile(self, by, *extra, session=None):
        result = self.run_tool("profile", "--session", str(session or self.session),
                               "--by", by, *extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def document(self, by, *extra, session=None):
        return json.loads(self.profile(by, "--json", *extra, session=session))

    def symbolized(self, by, *extra):
        return self.profile(by, "--image-path", str(timer_fixture.IMAGE_DIR), *extra)


class TimerFixtureTest(unittest.TestCase):
    """The committed tables belong to the committed image: every image sample lies in one of the
    Function ranges uProf resolved from its PDB, and no host path is left in the fixture."""

    def test_every_image_sample_lies_in_a_pdb_function_range(self):
        tables = timer_fixture.tables()

        def records(name):
            columns = [column for column, _kind in tables[name]["columns"]]
            return [dict(zip(columns, row)) for row in tables[name]["rows"]]

        image_ids = {row["id"] for row in records("Module")
                     if row["path"] == "c:\\fixture\\heap_churn.exe"}
        ranges = [(row["startOffset"], row["startOffset"] + row["size"])
                  for row in records("Function") if row["moduleId"] in image_ids]
        rvas = {row["moduleRVA"] for row in records("UnifiedSampleSeries")
                if row["moduleId"] in image_ids}
        self.assertTrue(ranges and rvas)
        outside = sorted(rva for rva in rvas if not any(lo <= rva < hi for lo, hi in ranges))
        self.assertEqual(outside, [])
        self.assertEqual(sum(row[timer_fixture.EVENT_COLUMN]
                             for row in records("UnifiedSampleSeries")), TOTAL)

    def test_fixture_holds_no_host_path(self):
        for name in ("session.uprof", "cpu_tables.json", "heap_churn.pdb", "heap_churn.exe"):
            data = (timer_fixture.FIXTURE / name).read_bytes().lower()
            for marker in (b"users", b"repositories", b"worktree"):
                with self.subTest(name=name, marker=marker):
                    self.assertNotIn(marker, data)
                    self.assertNotIn(marker.decode().encode("utf-16-le"), data)


class TimerDetectionTest(_Session):
    """REQ-01: the recorded timer config, not configName, marks a timer capture."""

    def test_fixture_session_is_a_timer_capture(self):
        sampler = uprof_session.derive_sampler(self.session)
        self.assertTrue(sampler.timer)
        self.assertTrue(sampler.pmc)
        self.assertEqual(sampler.event_column, timer_fixture.EVENT_COLUMN)
        self.assertEqual(sampler.interval_ms, 1.0)
        self.assertFalse(sampler.os_requested)

    def test_reduced_session_derives_the_same_sampler_as_a_full_one(self):
        full = timer_fixture.meta()
        full["deviceInfo"] = {"cpu": "any"}
        full["collection"]["events"]["configName"] = "Custom Profile"
        session = self.root / "full"
        session.mkdir()
        (session / "session.uprof").write_text(json.dumps(full), encoding="utf-8")
        self.assertEqual(uprof_session.derive_sampler(session),
                         uprof_session.derive_sampler(self.session))

    def test_cpu_time_without_its_hw_event_id_is_not_a_timer(self):
        meta = timer_fixture.meta()
        for category in meta["auxiliary"]["eventColumnIds"]:
            for event in category["events"]:
                event["hwEventId"] = 1
        session = self.root / "other"
        session.mkdir()
        (session / "session.uprof").write_text(json.dumps(meta), encoding="utf-8")
        self.assertFalse(uprof_session.derive_sampler(session).timer)

    def test_a_pmc_event_wins_over_a_timer_entry(self):
        meta = timer_fixture.meta()
        meta["collection"]["events"]["pmcEvents"] = {"pmcEventList": [{
            "hwId": 118, "interval": 2_600_000, "isSampling": True, "os": True,
            "encodedEventId": 0x03000076}]}
        session = self.root / "mixed"
        session.mkdir()
        (session / "session.uprof").write_text(json.dumps(meta), encoding="utf-8")
        sampler = uprof_session.derive_sampler(session)
        self.assertFalse(sampler.timer)
        self.assertTrue(sampler.pmc_cycle_shares)

    def test_missing_sample_column_fails_with_cause_and_alternative(self):
        session = timer_fixture.build(self.root / "nocol",
                                      drop_columns=(timer_fixture.EVENT_COLUMN,))
        result = self.run_tool("profile", "--session", str(session), "--by", "process")
        self.assertEqual(result.returncode, 2)
        lines = result.stderr.strip().splitlines()
        self.assertTrue(lines[0].startswith("error: cpu.db UnifiedSampleSeries has no "
                                            f"{timer_fixture.EVENT_COLUMN} column"), lines[0])
        self.assertEqual(_labels(result.stderr), ["translate without dump"])


class TimerOutputTest(_Session):
    """REQ-02/03/04/11/18/19: one METRIC line names the mode and every missing measure."""

    def test_metric_line_is_exact_and_once_in_text_and_json(self):
        text = self.profile("module")
        self.assertEqual(text.count("METRIC: "), 1)
        self.assertIn(METRIC + "\n", text)
        document = self.document("module")
        self.assertEqual("METRIC: " + document["METRIC"], METRIC)

    def test_system_wide_metric_states_the_unverified_denominator(self):
        meta = timer_fixture.meta()
        meta["collection"]["target"]["systemWide"] = True
        session = timer_fixture.build(self.root / "wide", meta_override=meta)
        self.assertIn(METRIC_WIDE + "\n", self.profile("process", session=session))

    def test_no_kernel_coverage_line(self):
        for by in ("process", "module"):
            with self.subTest(by=by):
                self.assertNotIn("KERNEL_COVERAGE", self.profile(by))

    def test_absent_measures_are_named_once_in_text(self):
        for by in ("process", "module"):
            with self.subTest(by=by):
                text = self.profile(by)
                header = text.split("\n|", 1)[0]
                self.assertEqual(header.count("time_share"), 1, header)
                self.assertEqual(header.count("tag_to_retire_share"), 1, header)
                self.assertNotIn("TIME_SHARE:", header)
                self.assertNotIn("TAG_TO_RETIRE_SHARE:", header)

    def test_parent_line_does_not_repeat_the_absent_measures(self):
        reason = _symbolizer_skip()
        if reason:
            self.skipTest(reason)
        text = self.symbolized("instruction", "--function", HASH_NAME,
                               "--module", timer_fixture.IMAGE_KEY)
        header = text.split("\n|", 1)[0]
        self.assertEqual(header.count("time_share absent"), 0, header)
        self.assertEqual(header.count("tag_to_retire_share absent"), 0, header)
        self.assertEqual(header.count("tag_to_retire_share"), 1, header)

    def test_columns_and_ordering(self):
        document = self.document("module")
        rows = document["rows"]
        self.assertNotIn("time_share", rows[0])
        self.assertNotIn("tag_to_retire_share", rows[0])
        self.assertNotIn("cpu_seconds", rows[0])
        shares = [row["sample_share"] for row in rows]
        self.assertAlmostEqual(sum(shares), 1.0)
        self.assertEqual(shares, sorted(shares, reverse=True))
        self.assertEqual(document["legend"]["impact"]["primary_measure"], "sample_share")

    def test_json_absent_causes_are_the_timer_causes(self):
        absent = self.document("module")["legend"]["absent"]
        self.assertEqual(absent["time_share"], "a timer capture has no per-sample timestamps")
        self.assertEqual(absent["tag_to_retire_share"],
                         "a timer capture has no tag-to-retire counter")
        self.assertIn("multiply sample_share by the workload's measured CPU time",
                      absent["cpu_seconds"])

    def test_no_pmc_or_cycle_wording_in_timer_output(self):
        for by in ("process", "module"):
            for extra in ((), ("--json",)):
                with self.subTest(by=by, json=bool(extra)):
                    text = self.profile(by, *extra)
                    for banned in ("PMC", "core-cycle", "time-based", "Time-based Sampling",
                                   "configName", "--event ibs-op", "--event cycles"):
                        self.assertNotIn(banned, text)

    def test_module_rows_keep_the_external_share(self):
        rows = {row["module"]: row for row in self.document("module")["rows"]}
        image = rows[timer_fixture.IMAGE_KEY]
        ntdll = rows[timer_fixture.NTDLL_KEY]
        self.assertEqual(image["samples"], IMAGE_SAMPLES)
        self.assertFalse(image["isSystemModule"])
        self.assertAlmostEqual(image["sample_share"], IMAGE_SAMPLES / TOTAL)
        self.assertEqual(ntdll["samples"], NTDLL_SAMPLES)
        self.assertTrue(ntdll["isSystemModule"])
        self.assertAlmostEqual(ntdll["sample_share"], NTDLL_SAMPLES / TOTAL)

    def test_function_share_uses_the_capture_denominator(self):
        reason = _symbolizer_skip()
        if reason:
            self.skipTest(reason)
        document = json.loads(self.symbolized("function", "--json"))
        hashed = next(row for row in document["rows"] if row["function"] == HASH_NAME)
        self.assertEqual(hashed["samples"], HASH_SAMPLES)
        self.assertAlmostEqual(hashed["sample_share"], HASH_SAMPLES / TOTAL)

    def test_read_carries_the_top_row_interval(self):
        share = IMAGE_SAMPLES / TOTAL
        half = 1.96 * math.sqrt(share * (1 - share) / TOTAL)
        expected = (f"top row {timer_fixture.IMAGE_KEY} {100 * share:.1f}% "
                    f"±{100 * half:.1f} points (95% binomial, n={TOTAL})")
        read = re.search(r"^READ: .*$", self.profile("module"), re.M).group(0)
        self.assertTrue(read.endswith(expected), read)
        self.assertIn("72.8% ±2.3 points", expected)

    def test_read_states_no_interval_for_a_whole_share(self):
        read = re.search(r"^READ: .*$", self.profile("process"), re.M).group(0)
        self.assertTrue(read.endswith(f"100.0% (n={TOTAL}; no interval)"), read)

    def test_achieved_reports_the_busiest_thread_without_warning(self):
        achieved = re.search(r"^ACHIEVED: .*$", self.profile("process"), re.M).group(0)
        self.assertIn(f"{TOTAL} samples", achieved)
        self.assertIn("busiest thread", achieved)
        self.assertIn("1 active thread", achieved)
        self.assertNotIn("WARN", achieved)


class TimerModesTest(_Session):
    """REQ-05: every --by view runs on a timer capture."""

    def test_unsymbolized_views(self):
        for by in ("process", "module"):
            with self.subTest(by=by):
                self.assertIn("| sample_share |", self.profile(by))

    def test_symbolized_views(self):
        reason = _symbolizer_skip()
        if reason:
            self.skipTest(reason)
        for by in ("function", "region", "line", "instruction"):
            with self.subTest(by=by):
                self.assertIn("sample_share", self.symbolized(by))

    def test_hash_loop_lines_are_named(self):
        reason = _pdb_skip()
        if reason:
            self.skipTest(reason)
        document = json.loads(self.symbolized(
            "line", "--json", "--function", HASH_NAME, "--module", timer_fixture.IMAGE_KEY))
        lines = {row["line"] for row in document["rows"] if row["file"]}
        self.assertTrue(lines & {23, 24, 25}, lines)


class TimerFailureTest(_Session):
    """REQ-06/09/15/17: unsupported cases fail with a cause and ALTERNATIVE lines."""

    def test_profile_time_filter_fails_with_alternatives(self):
        result = self.run_tool("profile", "--session", str(self.session), "--by", "process",
                               "--time-filter", "0:1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.splitlines()[0],
                         "error: --time-filter applies to IBS dump captures; a timer capture "
                         "is windowed at translate time")
        self.assertEqual(_labels(result.stderr), ["timer window", "whole capture"])
        whole = _alternatives(result.stderr)[1]
        self.assertIn(f"profile --session {self.session}", whole.replace('"', ""))

    def test_translate_ascii_fails_with_alternative(self):
        result = self.run_tool("translate", "--session", str(self.session),
                               "--out-dir", str(self.root / "copy"),
                               "--ascii", "ibsop-event-dump")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.splitlines()[0],
                         "error: a timer capture has no IBS sample dump")
        self.assertEqual(_labels(result.stderr), ["translate without dump"])

    def test_translate_time_filter_is_passed_through(self):
        command = uprof_native.translate_command(FAKE_CLI, self.session, time_filter="0:1")
        self.assertIn("0:1", command)

    def test_session_without_a_sampler_offers_the_capture_alternatives(self):
        session = self.root / "none"
        session.mkdir()
        (session / "session.uprof").write_text(json.dumps({"collection": {}}), encoding="utf-8")
        with mock.patch.object(uprof_native, "find_uprof", return_value=Path(FAKE_CLI)):
            with self.assertRaises(uprof_native.UprofError) as raised:
                uprof_dump.resolve_dump(session, uprof_session.derive_sampler(session))
        text = str(raised.exception)
        self.assertEqual(text.splitlines()[0], "session.uprof records no IBS, PMC or timer event")
        self.assertEqual(_labels(text), ["timer capture", "timer capture (launch)", "Zen host"])
        self.assertNotIn("schema", text)

    def test_shared_alternatives_are_identical(self):
        with mock.patch.object(uprof_native, "find_uprof", return_value=Path(FAKE_CLI)):
            first = str(uprof_native.failure("a", ["timer capture (launch)", "Zen host"]))
            second = str(uprof_native.failure("b", ["Zen host", "timer capture (launch)"]))
        self.assertEqual(_alternatives(first), _alternatives(second))
        self.assertIn(f"ALTERNATIVE: timer capture (launch): {Path(FAKE_CLI)} collect --config tbp "
                      "-o <NEW_OUT_DIR> <APP>; python ", first)


class CollectRejectionTest(unittest.TestCase):
    """REQ-15: a rejected cycle event fails with alternatives; no other sampler is started."""

    def collect(self, event):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name) / "out"
        calls = []
        rejected = "ERROR: Invalid event(CYCLES_NOT_IN_HALT) specified with option(-e or --event)."

        def fake_run_cli(_uprof, spec, _target_args, _options):
            calls.append(spec)
            if "IBS" in spec.upper() and len(calls) == 1:
                return subprocess.CompletedProcess(spec, 1, "", "ibs counters are not available")
            return subprocess.CompletedProcess(spec, 2148008192, rejected, "")

        options = uprof_collect.CollectOptions(out_dir=str(out), seconds=5, pids=[4242],
                                               event=event)
        with mock.patch.object(uprof_collect, "is_admin", return_value=True), \
                mock.patch.object(uprof_collect, "find_uprof", return_value=FAKE_CLI), \
                mock.patch.object(uprof_collect, "require_uprof", return_value=FAKE_CLI), \
                mock.patch.object(uprof_native, "find_uprof", return_value=Path(FAKE_CLI)), \
                mock.patch.object(uprof_collect, "ibs_unavailable_reason", return_value="test"), \
                mock.patch.object(uprof_collect, "_run_cli", side_effect=fake_run_cli), \
                mock.patch.object(uprof_collect, "_core_frequency",
                                  return_value=(2_600_000_000, "2600 MHz", "test")), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(uprof_native.UprofError) as raised:
                uprof_collect.collect(options)
        return str(raised.exception), calls

    def test_rejected_cycle_event(self):
        for event, runs in (("cycles", 1), ("ibs-op", 2)):
            with self.subTest(event=event):
                text, calls = self.collect(event)
                self.assertEqual(len(calls), runs)
                self.assertTrue(text.splitlines()[0].startswith(
                    "AMDuProfCLI rejected CYCLES_NOT_IN_HALT: ERROR: Invalid event"), text)
                self.assertEqual(_labels(text), ["timer capture", "timer capture (launch)",
                                                 "whole capture", "Zen host"])
                timer = _alternatives(text)[0]
                self.assertIn("collect --config tbp -d 5 -o <NEW_OUT_DIR> -p 4242", timer)
                for line in _alternatives(text)[:3]:
                    self.assertNotIn("--event", line)


if __name__ == "__main__":
    unittest.main()
