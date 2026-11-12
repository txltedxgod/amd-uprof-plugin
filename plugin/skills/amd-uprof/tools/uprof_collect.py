"""Cycle or IBS capture with the metadata guard and the IBS capability probe.

uProf creates a fresh session directory. The marker recorded before the CLI call distinguishes
the session this run created from a stale session.uprof in the same parent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from uprof_native import (IS_WINDOWS, failure, failure_detail, find_uprof,
                          ibs_unavailable_reason, is_admin, print_output, require_uprof, run)
from uprof_session import collect_summary, verify_collect
from uprof_util import UprofError, absolute, skill_identity

_IBS_UNAVAILABLE = "ibs counters are not available"
# AMDuProfCLI's message when the CPU has no CYCLES_NOT_IN_HALT event (for example a non-AMD CPU).
_CYCLES_REJECTED = "invalid event(cycles_not_in_halt)"
_CYCLE_DEFAULT = "1ms"
_OP_DEFAULT = "1000000"
_KERNEL_COVERAGE_NOTE = "kernel-mode (OS) samples are omitted without elevation"
_FALLBACK_KERNEL_WARNING = ("WARNING: unelevated: the fallback cycle capture omits kernel-mode "
                            "(OS) samples without elevation")
_TIME_UNITS = {"ns": Decimal("0.000000001"), "us": Decimal("0.000001"),
               "ms": Decimal("0.001"), "s": Decimal(1)}
_TIME_INTERVAL = re.compile(r"^\s*(\d+(?:\.\d*)?|\.\d+)\s*(ns|us|ms|s)\s*$", re.IGNORECASE)
_WINDOWS_FREQUENCY_KEY = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"


@dataclass
class CollectOptions:
    """One capture request; out_dir keeps its argument spelling for the printed command."""

    out_dir: str
    seconds: int = 60
    pids: list[int] = field(default_factory=list)
    sample_interval: str | None = None  # time string in cycle modes, work count in op mode
    event: str = "cycles"  # cycles | ibs-op
    ibs_count_control: str = "op"  # op | cycles
    dry_run: bool = False


def _event_spec(options: CollectOptions, event: str, interval: int) -> str:
    if event == "cycles":
        return f"event=CYCLES_NOT_IN_HALT,interval={interval},user=1,os=1"
    controls = 0 if options.ibs_count_control == "cycles" else 1
    return f"event=ibs-op,ibsop-count-control={controls},interval={interval}"


def _requests_os_mode(event: str) -> bool:
    """True when the event collect applies asks the driver for OS-mode samples.

    The cycle spec passes user=1,os=1. The IBS event samples user and OS by default and collect
    exposes no user/os toggle, so both events request OS mode.
    """
    return event in ("cycles", "ibs-op")


def _unelevated_warning(os_requested: bool) -> str:
    """The capture-time warning; kernel coverage is a separate absence from elevated processes."""
    text = ("WARNING: unelevated: elevated processes (services, admin-started engines) may be "
            "missing from the capture")
    return f"{text}; {_KERNEL_COVERAGE_NOTE}" if os_requested else text


def _target_args(options: CollectOptions) -> tuple[list[str], str]:
    if not options.pids:
        return ["-a"], "-a"
    spec = ",".join(str(pid) for pid in options.pids)
    return ["-p", spec], f"-p {spec}"


def _interval_mode(options: CollectOptions) -> str:
    """cycles for a time interval, ops for the IBS dispatched-op work count."""
    return "cycles" if options.event == "cycles" or options.ibs_count_control == "cycles" else "ops"


def _core_frequency() -> tuple[int, str, str]:
    """The machine's reported core frequency: (Hz, printed value, source)."""
    if IS_WINDOWS:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINDOWS_FREQUENCY_KEY) as key:
                mhz = int(winreg.QueryValueEx(key, "~MHz")[0])
        except (ImportError, OSError, TypeError, ValueError):
            mhz = 0
        if mhz > 0:
            return (mhz * 1_000_000, f"{mhz} MHz",
                    "Windows registry HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\~MHz")
        raise UprofError(
            "cannot read the core frequency from the Windows registry "
            "(HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\~MHz); check that the "
            "~MHz value exists and is nonzero (Get-ItemProperty "
            "'HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0' '~MHz'), or capture with "
            "--event ibs-op --ibs-count-control op, whose interval is a work count")

    base_frequency = Path("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency")
    try:
        khz = int(base_frequency.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        khz = 0
    if khz > 0:
        return khz * 1000, f"{khz / 1000:g} MHz", str(base_frequency)
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cpuinfo = ""
    match = re.search(r"(?mi)^\s*cpu MHz\s*:\s*(\d+(?:\.\d+)?)\s*$", cpuinfo)
    if match:
        hz = int((Decimal(match.group(1)) * 1_000_000).to_integral_value(rounding=ROUND_HALF_UP))
        if hz > 0:
            return hz, f"{match.group(1)} MHz", "/proc/cpuinfo cpu MHz"
    raise UprofError(
        "cannot determine the core frequency: neither "
        "/sys/devices/system/cpu/cpu0/cpufreq/base_frequency nor a 'cpu MHz' line in /proc/cpuinfo "
        "is available; check that cpufreq exposes cpu0, or capture with --event ibs-op "
        "--ibs-count-control op, whose interval is a work count")


def _resolve_interval(options: CollectOptions, mode: str,
                      text: str | None = None) -> tuple[int, str]:
    """Convert --sample-interval to cycles or ops and return (value, printed line)."""
    if text is None:
        text = options.sample_interval
    if text is None:
        text = _OP_DEFAULT if mode == "ops" else _CYCLE_DEFAULT
    text = str(text).strip()
    if mode == "ops":
        if _TIME_INTERVAL.match(text):
            raise UprofError(
                f"--sample-interval {text!r} is a time, but IBS op-count mode takes a positive "
                "integer work count (dispatched ops), not time; pass a work count such as "
                "1000000, or use --ibs-count-control cycles for a time interval")
        try:
            ops = int(text)
        except ValueError:
            raise UprofError(
                f"--sample-interval in IBS op-count mode must be a positive integer work count "
                f"(got {text!r}); it is not a time") from None
        if ops <= 0:
            raise UprofError(f"--sample-interval work count must be positive (got {ops})")
        return ops, f"SAMPLE_INTERVAL={text} ops (work count, not time)"

    match = _TIME_INTERVAL.match(text)
    if not match:
        try:
            int(text)
        except ValueError:
            raise UprofError(
                f"--sample-interval must be a time with a unit (ns, us, ms, s), e.g. 200us or "
                f"1ms; got {text!r}") from None
        raise UprofError(
            f"--sample-interval {text!r} has no unit; in cycle mode it is a time, so add ns, us, "
            f"ms or s (for example {text}us)")
    seconds = Decimal(match.group(1)) * _TIME_UNITS[match.group(2).lower()]
    if seconds <= 0:
        raise UprofError(f"--sample-interval must be positive (got {text!r})")
    frequency_hz, frequency_text, source = _core_frequency()
    cycles = int((seconds * frequency_hz).to_integral_value(rounding=ROUND_HALF_UP))
    if cycles <= 0:
        raise UprofError(f"--sample-interval {text!r} converts to 0 cycles at {frequency_text}; "
                         "use a longer time")
    return cycles, (f"SAMPLE_INTERVAL={text} -> {cycles} cycles at {frequency_text} "
                    f"(source: {source})")


def _validate(options: CollectOptions) -> None:
    if options.seconds <= 0:
        raise UprofError(f"--seconds must be positive (got {options.seconds})")
    if options.pids:
        invalid = [pid for pid in options.pids if pid is None or pid <= 0]
        if invalid:
            raise UprofError("--process needs positive PID(s); invalid: "
                             + ", ".join(str(pid) for pid in invalid))
    if options.event == "cycles" and options.ibs_count_control != "op":
        raise UprofError("--ibs-count-control is only valid with --event ibs-op")


def _run_cli(uprof: str, event_spec: str, target_args: list[str],
             options: CollectOptions) -> subprocess.CompletedProcess[str]:
    command = [uprof, "collect", "-e", event_spec, *target_args,
               "-d", str(options.seconds), "-o", options.out_dir]
    completed = run(command, timeout=max(300, options.seconds * 3 + 120))
    print_output(completed)
    return completed


def _session_marker(out_dir: Path) -> tuple[bool, bool, set[Path]]:
    existed = out_dir.is_dir()
    session_before = existed and (out_dir / "session.uprof").is_file()
    children: set[Path] = set()
    if existed:
        children = {child for child in out_dir.iterdir() if child.is_dir()}
    return existed, session_before, children


def _new_sessions(out_dir: Path, session_before: bool, children_before: set[Path]) -> list[Path]:
    found: list[Path] = []
    if not out_dir.is_dir():
        return found
    if not session_before and (out_dir / "session.uprof").is_file():
        found.append(out_dir)
    for child in out_dir.iterdir():
        if (child.is_dir() and child not in children_before
                and (child / "session.uprof").is_file()):
            found.append(child)
    return found


def _discard_failed_attempt(out_dir: Path, existed: bool, children_before: set[Path]) -> None:
    """Remove directories the failed IBS run created, so the fallback starts clean."""
    if not existed and out_dir.is_dir():
        shutil.rmtree(out_dir, ignore_errors=True)
        return
    if not out_dir.is_dir():
        return
    for child in out_dir.iterdir():
        if child.is_dir() and child not in children_before:
            shutil.rmtree(child, ignore_errors=True)


def _one_session(out_dir: Path, session_before: bool, children_before: set[Path]) -> Path:
    sessions = _new_sessions(out_dir, session_before, children_before)
    if not sessions:
        raise UprofError(f"uProf created no session under {out_dir}; expected a new session.uprof "
                         "in that directory or in a new AMDuProf-* child")
    if len(sessions) > 1:
        raise UprofError(f"uProf created {len(sessions)} sessions under {out_dir} "
                         f"({', '.join(str(session) for session in sessions)}); expected one")
    return sessions[0]


def collect(options: CollectOptions) -> None:
    _validate(options)
    mode = _interval_mode(options)
    interval, interval_line = _resolve_interval(options, mode)
    out_dir = Path(options.out_dir)
    # --dry-run prints the command without requiring the CLI to be installed.
    uprof_display = find_uprof() or "AMDuProfCLI"
    target_args, target_display = _target_args(options)
    print(f"VERSION={skill_identity()}")
    print(interval_line)
    print(f"EVENT={_event_spec(options, options.event, interval)}")
    print(f'COMMAND="{uprof_display}" collect -e {_event_spec(options, options.event, interval)} '
          f'{target_display} -d {options.seconds} -o "{options.out_dir}"')
    elevated = is_admin()
    print(f"Elevated={elevated}")
    os_requested = _requests_os_mode(options.event)
    if not elevated:
        print(_unelevated_warning(os_requested), file=sys.stderr)
    if out_dir.is_dir():
        print(f"WARNING: {options.out_dir} exists; uProf will create an AMDuProf-* subdirectory "
              "to avoid the collision", file=sys.stderr)
    if options.dry_run:
        print("DRYRUN=1")
        return
    uprof = require_uprof()

    existed, session_before, children_before = _session_marker(out_dir)
    effective_event = options.event
    completed = _run_cli(uprof, _event_spec(options, effective_event, interval), target_args,
                         options)
    combined = ((completed.stdout or "") + "\n" + (completed.stderr or "")).lower()
    if (completed.returncode != 0 and options.event == "ibs-op"
            and _IBS_UNAVAILABLE in combined):
        reason = ibs_unavailable_reason()
        print(f"SAMPLER: falling back to cycle sampling (time-based); IBS unavailable: {reason}")
        _discard_failed_attempt(out_dir, existed, children_before)
        existed, session_before, children_before = _session_marker(out_dir)
        effective_event = "cycles"
        if mode != "cycles":
            # An op count is not a time; the fallback uses the documented cycle default.
            interval, interval_line = _resolve_interval(options, "cycles", text=_CYCLE_DEFAULT)
            print(interval_line)
        cycle_spec = _event_spec(options, effective_event, interval)
        print(f'COMMAND="{uprof_display}" collect -e {cycle_spec} {target_display} '
              f'-d {options.seconds} -o "{options.out_dir}"')
        # The fallback cycle capture always requests OS mode; only elevation decides the warning.
        if not elevated:
            print(_FALLBACK_KERNEL_WARNING, file=sys.stderr)
        completed = _run_cli(uprof, cycle_spec, target_args, options)
    if completed.returncode != 0:
        detail = failure_detail(completed)
        if (effective_event == "cycles"
                and _CYCLES_REJECTED in ((completed.stdout or "") + (completed.stderr or "")).lower()):
            # No other sampler is started on this host's behalf; the caller picks one.
            raise failure(f"AMDuProfCLI rejected CYCLES_NOT_IN_HALT: {detail}",
                          ["timer capture", "timer capture (launch)", "whole capture",
                           "Zen host"])
        raise UprofError(f"collect failed with {completed.returncode}: {detail}")

    session = _one_session(out_dir, session_before, children_before)
    print(f"SESSION={absolute(session)}")
    meta = verify_collect(session, effective_event, interval,
                          options.ibs_count_control, not options.pids, options.pids)
    print(f"collectCommand={meta.get('collectCommand')}")
    print(collect_summary(meta, effective_event))
