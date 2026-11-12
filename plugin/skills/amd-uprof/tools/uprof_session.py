"""Read session.uprof and decide what the capture's sample shares mean.

The sampler, interval and cycle-vs-op control come from collection.events.ibsEvents and
pmcEvents.pmcEventList. collectCommand is only a fallback: a --config capture records no event=
there. Nothing here reads a documented constant instead of the capture.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from uprof_util import UprofError

PMC_EVENT = "event#0x3000076"
IBS_OP_EVENT = "event#0x100000000f100"
IBS_FETCH_EVENT = "event#0x100000000f000"

@dataclass
class Sampler:
    """What session.uprof records, and therefore what its sample shares mean.

    ibs_dump_kind is a DUMP_FILENAMES key when an IBS ASCII dump exists; metric is the METRIC
    line printed before query results. pmc marks a capture whose samples come from cpu.db rather
    than a dump (a PMC capture, or a timer capture with timer set); event_column names its sample
    column in UnifiedSampleSeries.
    os_requested is the applied event's OS-mode bit; an unelevated capture that requests it has no
    kernel-image samples, which kernel_coverage_warning checks. os_mode names the bit that carried
    the request (os, opOs or fetchOs) for the warning text. pmc_cycle_shares is true only for a
    PMC event that is hwId 118 with isSampling, whose fixed cycles make sample_share a busy
    core-cycle share; any other PMC event leaves the share's meaning not established.
    """

    ibs_dump_kind: str | None = None
    metric: str = "METRIC: session.uprof not found -- metric basis not established"
    pmc: bool = False
    pmc_cycle_shares: bool = False
    event_column: str | None = None
    interval: int | None = None
    interval_units: str | None = None  # 'cycles' (time-convertible), 'ops' or 'fetch' (not)
    os_requested: bool = False
    os_mode: str | None = None
    # A timer capture reads cpu.db like PMC (pmc is set too); its interval is milliseconds.
    timer: bool = False
    interval_ms: float | None = None
    system_wide: bool = False


@dataclass
class ContextCadence:
    """One sampling context's sample count and delivered cadence.

    A context is a CPU for a system-wide capture, a TID for an attached capture, or a core for a
    PMC capture. median_gap_ns is the median DeltaTick gap between consecutive samples whose gap
    is at most ten times the requested interval (a larger gap is the context not running); None
    when the source has no per-sample timestamps or the context never sampled twice inside that
    limit.
    """

    samples: int
    median_gap_ns: float | None = None


# A gap above this multiple of the request is time the context was not sampling continuously.
_RUN_GAP_FACTOR = 10.0


def read_meta(session_dir: Path | str) -> dict[str, Any] | None:
    path = Path(session_dir) / "session.uprof"
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return {}


def records_true(value: Any) -> bool:
    """True only for the JSON string true, matching v_capture_span.system_wide in views.sql."""
    return str(value).lower() == "true"


def system_wide(session_dir: Path | str) -> bool:
    """True when session.uprof records a system-wide target; False for attached or unknown.

    Only the string true counts, matching the v_capture_span.system_wide test in views.sql, so a
    non-boolean value cannot make the Python legend and the SQL weighting disagree.
    """
    meta = read_meta(session_dir) or {}
    return records_true(((meta.get("collection") or {}).get("target") or {}).get("systemWide"))


def _registered_columns(meta: dict[str, Any]) -> dict[str, str]:
    columns: dict[str, str] = {}
    for category in (meta.get("auxiliary") or {}).get("eventColumnIds") or []:
        for event in category.get("events") or []:
            name = event.get("name")
            encoded = event.get("encodedId")
            if name and encoded is not None:
                columns.setdefault(str(name), f"event#0x{int(encoded):x}")
    return columns


def _encoded_name(event: dict[str, Any]) -> str | None:
    """The event#0x... spelling of the entry's encodedEventId; None when it has none."""
    encoded = event.get("encodedEventId")
    return f"event#0x{int(encoded):x}" if encoded is not None else None


def _event_from_command(meta: dict[str, Any]) -> str | None:
    match = re.search(r"event=([^,\s]+)", str(meta.get("collectCommand") or ""))
    return match.group(1) if match else None


def _ibs_os_mode(ibs: dict[str, Any] | None) -> str | None:
    """The OS-mode bit name(s) of the enabled IBS samplers, or None when none requested OS mode.

    A session can record both op and fetch; each enabled sampler carries its own bit.
    """
    if not ibs:
        return None
    bits = [name for name, enabled in (("opOs", ibs.get("op")), ("fetchOs", ibs.get("fetch")))
            if enabled and ibs.get(name)]
    return ", ".join(bits) or None


def derive_sampler(session_dir: Path | str) -> Sampler:
    meta = read_meta(session_dir)
    if meta is None:
        return Sampler()
    if not meta:
        return Sampler(metric="METRIC: session.uprof is not readable JSON -- metric basis not established")

    columns = _registered_columns(meta)
    from_command = _event_from_command(meta)
    ibs = (meta.get("collection") or {}).get("events", {}).get("ibsEvents")
    is_ibs = bool((meta.get("auxiliary") or {}).get("ibsOpSampling")) or bool(
        ibs and (ibs.get("op") or ibs.get("fetch")))

    if is_ibs:
        os_mode = _ibs_os_mode(ibs)
        if ibs and ibs.get("op"):
            event = columns.get("IBS_ALL_OPS", IBS_OP_EVENT)
            interval = ibs.get("opInterval")
            if bool(ibs.get("opCycleCount")):
                metric = (f"METRIC: IBS OP (IBS_ALL_OPS {event}, cycle-controlled interval {interval}) "
                          "-- sample shares: core-cycle share (fixed cycles per sample), not "
                          "wall time, not a per-op cost; tag-to-retire: share of tag-to-retire "
                          "cycles summed over sampled ops (dispatch tag to retirement, "
                          "queue/stalls included), clipped at 65535")
            else:
                metric = (f"METRIC: IBS OP (IBS_ALL_OPS {event}, op-count interval {interval}) "
                          "-- sample shares: dispatched-op frequency share (fixed dispatched "
                          "ops per sample), not a per-op cost; tag-to-retire: share of "
                          "tag-to-retire cycles summed over sampled ops (dispatch tag to "
                          "retirement, queue/stalls included), clipped at 65535")
            return Sampler(ibs_dump_kind="ibsop-event-dump", metric=metric, interval=interval,
                           interval_units="cycles" if bool(ibs.get("opCycleCount")) else "ops",
                           os_requested=os_mode is not None, os_mode=os_mode)
        if ibs and ibs.get("fetch"):
            event = columns.get("IBS_FETCH", IBS_FETCH_EVENT)
            metric = (f"METRIC: IBS fetch (IBS_FETCH {event}, interval {ibs.get('fetchInterval')}) "
                      "-- sample shares: fetch-sample frequency share (fixed fetch events per "
                      "sample); fetch path unverified")
            return Sampler(ibs_dump_kind="ibsfetch-event-dump", metric=metric,
                           interval=ibs.get("fetchInterval"), interval_units="fetch",
                           os_requested=os_mode is not None, os_mode=os_mode)
        return Sampler(metric=(
            "METRIC: IBS capture (details not recorded in session.uprof) -- sample shares: "
            "not established; do not read them as time"),
            os_requested=os_mode is not None, os_mode=os_mode)

    pmc = [event for event in
           ((meta.get("collection") or {}).get("events", {}).get("pmcEvents") or {}).get("pmcEventList") or []
           if event]
    if pmc:
        mapped = columns.get("CYCLES_NOT_IN_HALT")
        event = next((entry for entry in pmc if entry.get("hwId") == 118), None)
        if event is None and mapped is not None:
            event = next((entry for entry in pmc if _encoded_name(entry) == mapped), None)
        if event is None:
            event = pmc[0]
        expected = _encoded_name(event)
        column = mapped if mapped is not None else (expected or PMC_EVENT)
        if mapped is not None and mapped != expected:
            raise UprofError(
                f"session.uprof is inconsistent: auxiliary.eventColumnIds maps "
                f"CYCLES_NOT_IN_HALT to {mapped}, but the hwId {event.get('hwId')} entry in "
                f"pmcEventList has encodedEventId {expected or 'none'}; re-run the capture or "
                "regenerate session.uprof")
        if event.get("hwId") == 118:
            name = "CYCLES_NOT_IN_HALT"
        elif from_command:
            name = from_command
        else:
            name = f"hwId {event.get('hwId')}"
        cycle_shares = event.get("hwId") == 118 and bool(event.get("isSampling"))
        if cycle_shares:
            metric = (f"METRIC: {name} ({column}, hwId {event.get('hwId')}, "
                      f"interval {event.get('interval')}) -- sample shares: busy core-cycle "
                      "share (fixed cycles per sample; halted excluded)")
        else:
            metric = (f"METRIC: {name} (hwId {event.get('hwId')}, interval {event.get('interval')}, "
                      f"isSampling={event.get('isSampling')}) -- sample shares: not established; "
                      "this PMC event is not the supported cycle event")
        return Sampler(metric=metric, pmc=True, pmc_cycle_shares=cycle_shares,
                       event_column=column, interval=event.get("interval"),
                       interval_units="cycles", os_requested=bool(event.get("os")),
                       os_mode="os" if event.get("os") else None)

    timer = _timer_sampler(meta)
    if timer is not None:
        return timer

    if from_command:
        metric = (f"METRIC: {from_command} (from collectCommand; session.uprof records no PMC or IBS "
                  "event) -- sample shares: not established")
    else:
        metric = "METRIC: no PMC or IBS event recorded in session.uprof -- sample shares: not established"
    return Sampler(metric=metric)


TIMER_EVENT_NAME = "CPU_TIME"
TIMER_HW_EVENT_ID = 0xE000


def _timer_sampler(meta: dict[str, Any]) -> Sampler | None:
    """The sampler of a timer capture, or None when the session is not one.

    A timer capture records no IBS or PMC event, a positive collection.events.timerInterval in
    milliseconds, and one CPU_TIME event column (hwEventId 0xE000). The recorded configuration
    name differs between --config tbp and -e event=timer, so it is not used. The OS/user mode bits
    of the CPU_TIME entry do not describe the capture, so no OS-mode request is derived from them.
    """
    events = (meta.get("collection") or {}).get("events") or {}
    try:
        interval_ms = float(events.get("timerInterval"))
    except (TypeError, ValueError):
        return None
    if not interval_ms > 0:
        return None
    column = None
    for category in (meta.get("auxiliary") or {}).get("eventColumnIds") or []:
        for event in category.get("events") or []:
            if (event.get("name") == TIMER_EVENT_NAME
                    and event.get("hwEventId") == TIMER_HW_EVENT_ID
                    and event.get("encodedId") is not None):
                column = f"event#0x{int(event['encodedId']):x}"
                break
        if column:
            break
    if column is None:
        return None
    wide = records_true(((meta.get("collection") or {}).get("target") or {}).get("systemWide"))
    unverified = "; system-wide denominator and idle handling unverified" if wide else ""
    metric = (f"METRIC: timer sampling ({TIMER_EVENT_NAME}, interval {interval_ms:g} ms) -- sample "
              "shares: on-CPU time share of the sampled threads (one sample per timer tick that "
              "found the thread running; kernel-mode ticks not established"
              f"{unverified}), not cycles, not wall time; not available from a timer capture: "
              "time_share, tag_to_retire_share, cycle cost, per-op cost, caller attribution into "
              "external modules")
    return Sampler(metric=metric, pmc=True, event_column=column, interval_units="ms",
                   timer=True, interval_ms=interval_ms, system_wide=wide)


def kernel_coverage_warning(sampler: Sampler, has_kernel_samples: bool,
                            captured_samples: int | None = None) -> str | None:
    """The warning when the applied sampler requested OS mode but no sample is in a kernel image.

    has_kernel_samples covers the whole capture, before any process or time filter; a user-mode-only
    request is expected to have none, so only an OS-mode request can warn. captured_samples is the
    whole capture's sample count: zero is an empty capture, a different observable from a
    populated capture that never sampled the kernel. None means the count is unknown.
    """
    if not sampler.os_requested or has_kernel_samples:
        return None
    bit = sampler.os_mode or "OS mode"
    if captured_samples == 0:
        return (f"no samples in the capture: the applied sampler requested OS mode ({bit}), but "
                "the capture holds no sample of any kind, so kernel coverage cannot be assessed. "
                "An attached process that exits before the first sample produces this; re-run "
                "the capture if it was expected to have samples")
    return (f"no kernel-image samples: the applied sampler requested OS mode ({bit}), but the "
            "whole capture has no sample in any kernel image, so kernel-mode samples are absent. "
            "If the capture was not elevated, only an elevated capture includes them")


def verify_collect(session_dir: Path | str, event: str, interval: int, count_control: str,
                   system_wide: bool, pids: list[int]) -> dict[str, Any]:
    """Check the applied event against the request; return the metadata for printing."""
    meta = read_meta(session_dir)
    if not meta:
        raise UprofError(f"session.uprof is missing or unreadable in {session_dir}")
    target = (meta.get("collection") or {}).get("target") or {}
    collection_event = ((meta.get("collection") or {}).get("events") or {})
    if event == "cycles":
        pmc = ((collection_event.get("pmcEvents") or {}).get("pmcEventList") or [])
        if not pmc:
            raise UprofError("no PMC event recorded; this is not a cycle capture")
        applied = pmc[0]
        if applied.get("hwId") != 118:
            raise UprofError(f"PMC event is hwId {applied.get('hwId')}, not PMCx076 (118)")
        if applied.get("interval") != interval:
            raise UprofError(f"interval is {applied.get('interval')}, expected {interval}")
        if not applied.get("isSampling"):
            raise UprofError("PMC event is not sampling")
        if (meta.get("auxiliary") or {}).get("ibsOpSampling"):
            raise UprofError("capture is IBS, not PMC cycle counting")
    else:
        ibs = collection_event.get("ibsEvents") or {}
        if not ibs.get("op"):
            raise UprofError("no IBS OP event recorded; this is not an IBS OP capture")
        if not (meta.get("auxiliary") or {}).get("ibsOpSampling"):
            raise UprofError("capture metadata says IBS OP sampling is off")
        if ibs.get("opInterval") != interval:
            raise UprofError(f"IBS interval is {ibs.get('opInterval')}, expected {interval}")
        if bool(ibs.get("opCycleCount")) != (count_control == "cycles"):
            raise UprofError(f"IBS count control is opCycleCount={ibs.get('opCycleCount')}, "
                             f"expected {count_control == 'cycles'} ({count_control})")
    if records_true(target.get("systemWide")) != system_wide:
        raise UprofError(f"capture target mode is systemWide={target.get('systemWide')}, "
                         f"expected {system_wide} (use -a or --process)")
    if not system_wide:
        attached = {int(entry.get("processId")) for entry in target.get("attachedProcesses") or []
                    if entry.get("processId") is not None}
        missing = [pid for pid in pids if pid not in attached]
        if missing:
            raise UprofError("capture did not attach to PID(s): " + ", ".join(map(str, missing)))
    return meta


def collect_summary(meta: dict[str, Any], event: str) -> str:
    collection_event = ((meta.get("collection") or {}).get("events") or {})
    target = (meta.get("collection") or {}).get("target") or {}
    auxiliary = meta.get("auxiliary") or {}
    if event == "cycles":
        applied = (((collection_event.get("pmcEvents") or {}).get("pmcEventList")) or [{}])[0]
        return (f"hwId={applied.get('hwId')} interval={applied.get('interval')} "
                f"isSampling={applied.get('isSampling')} systemWide={target.get('systemWide')} "
                f"ibsOpSampling={auxiliary.get('ibsOpSampling')}")
    ibs = collection_event.get("ibsEvents") or {}
    return (f"ibsOpSampling={auxiliary.get('ibsOpSampling')} ibsOp={ibs.get('op')} "
            f"opInterval={ibs.get('opInterval')} opCycleCount={ibs.get('opCycleCount')} "
            f"systemWide={target.get('systemWide')}")


def _format_duration(seconds: float) -> str:
    return (f"{seconds * 1e3:.3g} ms" if seconds >= 1e-3
            else f"{seconds * 1e6:.3g} us")


def requested_interval(sampler: Sampler, frequency_hz: float | None = None
                       ) -> tuple[float | None, str, str]:
    """The requested interval in seconds, the text naming it, and the ideal-rate note.

    interval_s is None for a work/fetch count or a cycle interval with no usable core frequency.
    frequency_hz reuses a frequency the caller already read; None reads the machine's reported
    one.
    """
    if sampler.timer and sampler.interval_ms:
        interval_s = sampler.interval_ms / 1000.0
        return (interval_s, f"timer {sampler.interval_ms:g} ms",
                f"; ideal {1.0 / interval_s:,.0f}/s per running thread")
    if sampler.interval is None or sampler.interval_units is None:
        return None, "the session records no interval", ""
    if sampler.interval_units == "cycles":
        try:
            if frequency_hz is None:
                from uprof_collect import _core_frequency
                hertz, display, _source = _core_frequency()
            else:
                hertz, display = float(frequency_hz), f"{frequency_hz / 1e6:g} MHz"
            interval_s = sampler.interval / hertz
            requested = (f"{sampler.interval} cycles at {display} = "
                         f"{_format_duration(interval_s)}")
            return interval_s, requested, f"; ideal {1.0 / interval_s:,.0f}/s per CPU"
        except Exception:
            return None, f"{sampler.interval} cycles (core frequency unavailable)", ""
    if sampler.interval_units == "ops":
        return (None, f"{sampler.interval} dispatched ops",
                "; the interval is a work count, so no time rate follows")
    return None, f"{sampler.interval} fetch events", ""


def run_gap_limit_ns(sampler: Sampler, frequency_hz: float | None = None) -> float | None:
    """The largest gap still counted as continuous sampling, in nanoseconds.

    None when the request carries no time interval; the caller then does not filter gaps.
    """
    interval_s, _requested, _ideal = requested_interval(sampler, frequency_hz)
    return None if interval_s is None else _RUN_GAP_FACTOR * interval_s * 1e9


def achieved_summary(samples: int, window_s: float | None, cpus: int, sampler: Sampler,
                     contexts: list[ContextCadence] | None = None,
                     context_label: str = "CPU",
                     frequency_hz: float | None = None) -> str:
    """The `ACHIEVED` text: whole-capture rate and the busiest sampling context's cadence.

    The per-CPU rate divides every sample by every CPU in the capture, so idle CPUs and
    intermittent threads make it read below the cadence a running context receives. contexts
    carries per-context sample counts and median running gaps; the warning is based only on the
    busiest context. A context is active when it holds at least 10% of the busiest context's
    samples. contexts is None only for callers with no per-context data, where no warning is
    possible.
    """
    interval_s, requested, ideal_note = requested_interval(sampler, frequency_hz)
    ideal_per_s = None if interval_s is None else 1.0 / interval_s

    if window_s is None or window_s <= 0:
        text = (f"{samples} samples; the capture records no usable duration, so the rate is "
                f"not derivable (requested {requested}{ideal_note})")
    elif cpus:
        rate = samples / window_s / cpus
        text = (f"{samples} samples, {window_s:.3f} s, {cpus} CPUs, {rate:,.2f}/s per CPU "
                f"(requested {requested}{ideal_note})")
    else:
        rate = samples / window_s
        text = (f"{samples} samples, {window_s:.3f} s, {rate:,.2f}/s over the capture "
                f"(requested {requested}{ideal_note}; the capture records no CPU id, so the "
                "per-CPU rate is not derivable)")

    below = False
    if contexts:
        busiest = max(contexts, key=lambda context: context.samples)
        if busiest.samples > 0:
            active = sum(1 for context in contexts
                         if context.samples >= 0.1 * busiest.samples)
            if busiest.median_gap_ns is not None and busiest.median_gap_ns > 0:
                delivered = 1e9 / busiest.median_gap_ns
                gap_s = busiest.median_gap_ns / 1e9
                text += (f"; busiest {context_label} {delivered:,.0f}/s "
                         f"(median gap {_format_duration(gap_s)})")
                below = (ideal_per_s is not None
                         and busiest.median_gap_ns > _RUN_GAP_FACTOR * interval_s * 1e9)
            elif sampler.ibs_dump_kind is not None:
                # The dump has timestamps, so no gap inside the limit means the context never
                # sampled continuously: exactly the condition the warning exists for.
                text += (f"; busiest {context_label} has no sampling run within "
                         f"{_RUN_GAP_FACTOR:g}x the requested interval")
                below = ideal_per_s is not None
            elif window_s is not None and window_s > 0:
                delivered = busiest.samples / window_s
                text += f"; busiest {context_label} {delivered:,.2f}/s"
                below = ideal_per_s is not None and delivered < 0.1 * ideal_per_s
            text += f"; {active} active {context_label if active == 1 else context_label + 's'}"
    if below:
        text += "; WARN: achieved sample rate is below 10% of the requested interval"
    return text


def anchor_report(session_dir: Path | str, qpc: int, freq: int | None) -> list[str]:
    """Map a QueryPerformanceCounter reading onto capture-relative seconds.

    collection.schedule.start/end are QPC-derived nanoseconds and each sample's DeltaTick is
    sample_ns - start, so a workload's own QPC reading converts with
    (qpc * 1e9 / freq - start) / 1e9. A reading taken before the capture started (negative)
    is attach latency: the capture does not cover it.
    """
    meta = read_meta(session_dir)
    if not meta:
        raise UprofError(f"session.uprof is missing or unreadable in {session_dir}")
    schedule = (meta.get("collection") or {}).get("schedule") or {}
    start = schedule.get("start")
    if start is None:
        raise UprofError("session.uprof records no collection.schedule.start; cannot anchor")
    from datetime import timezone

    hertz = freq or 10_000_000
    source = "argument" if freq else "default (10 MHz; the session records no QPC frequency)"
    relative = (qpc * 1e9 / hertz - int(start)) / 1e9
    lines = [
        f"QPC={qpc} HZ={hertz} HZ_SOURCE={source}",
        f"START_NS={int(start)}",
        f"RELATIVE_S={relative:.9f}",
    ]
    stamp = schedule.get("startTs")
    if stamp:
        parsed = _parse_start_ts(str(stamp))
        if parsed is not None:
            utc = parsed.astimezone(timezone.utc)
            lines.append(f"START_LOCAL={parsed.isoformat()}")
            lines.append(f"START_UTC={utc:%Y-%m-%dT%H:%M:%S}Z (precision: one second)")
        else:
            lines.append(f"START_TS={stamp} (unparsed; no UTC conversion)")
    else:
        lines.append("START_TS=absent (no UTC conversion)")
    if relative < 0:
        lines.append("NOTE=RELATIVE_S is negative: the reading precedes the capture start "
                     "(attach latency); the capture does not cover it")
    else:
        lines.append("NOTE=RELATIVE_S is seconds from capture start, comparable to "
                     "--time-filter")
    return lines


def _parse_start_ts(text: str):
    """schedule.startTs is local time with a single-digit day, e.g. 'Sat Nov  7 12:56:23 2026'."""
    import datetime

    collapsed = re.sub(r"\s+", " ", text.strip())
    try:
        parsed = datetime.datetime.strptime(collapsed, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return parsed.astimezone()
