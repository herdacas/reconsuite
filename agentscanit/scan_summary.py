#!/usr/bin/env python3
"""
scan_summary.py — AgentScanIT log summarizer

Usage:
    python3 scan_summary.py              # all scans, standard format
    python3 scan_summary.py --last 6     # last 6 scans
    python3 scan_summary.py --verbose    # with tool-call details
    python3 scan_summary.py --last 3 --verbose
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

LOGS_DIR = Path(__file__).parent / "logs"
WIDTH = 74


# ── helpers ──────────────────────────────────────────────────────────────────

def fmt_ts(ts: str) -> str:
    """'20260524_023930' → '2026-05-24 02:39'"""
    try:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}"
    except Exception:
        return ts


def truncate(text: str, max_len: int) -> str:
    s = str(text)
    return s[: max_len - 1] + "…" if len(s) > max_len else s


def shorten_path(part: str, max_len: int = 48) -> str:
    if len(part) > max_len and "/" in part:
        return "…/" + part.rsplit("/", 1)[-1]
    return part


def fmt_command(cmd) -> str:
    if isinstance(cmd, list):
        return " ".join(shorten_path(str(p)) for p in cmd)
    return str(cmd)


def extract_cve_ids(refs: list) -> list:
    ids = []
    for ref in refs:
        m = re.search(r"CVE-\d{4}-\d+", str(ref))
        if m and m.group(0) not in ids:
            ids.append(m.group(0))
    return ids


def error_reason(raw: str) -> str:
    raw = (raw or "").strip()
    if "timeout" in raw.lower() or raw.startswith("[TIMEOUT]"):
        return "TIMEOUT"
    m = re.match(r"\[TOOL_ERROR\]\s*[^:]+:\s*(.+)", raw)
    if m:
        return truncate(m.group(1).strip(), 42)
    return truncate(raw, 42) if raw else "ERROR"


# ── data loading ─────────────────────────────────────────────────────────────

def load_pair(crew_file: Path):
    """Return (crew_dict, trace_dict_or_None)."""
    crew = json.loads(crew_file.read_text())
    suffix = crew_file.name[len("crew_"):]          # "<target>_<TS>.json"
    trace_file = crew_file.parent / f"trace_{suffix}"
    trace = None
    if trace_file.exists():
        try:
            trace = json.loads(trace_file.read_text())
        except Exception:
            pass
    return crew, trace


def _phase_so(trace, phase: str) -> dict:
    """Structured output for a phase, or {}."""
    if not trace:
        return {}
    return trace.get("phases", {}).get(phase, {}).get("structured_output", {})


def open_ports(trace) -> list:
    for ph in ("blue", "red_scan"):
        ports = _phase_so(trace, ph).get("open_ports", [])
        if ports:
            return ports
    return []


def cve_refs(trace) -> list:
    for ph in ("findings", "red"):
        refs = _phase_so(trace, ph).get("cve_references", [])
        if refs:
            return refs
    return []


def vulnerabilities(crew, trace) -> list:
    for ph in ("blue", "red_scan", "findings", "red"):
        vulns = _phase_so(trace, ph).get("vulnerabilities", [])
        if vulns:
            return vulns[:3]
    # fallback to crew tasks
    for ph in ("blue", "findings", "red"):
        vulns = crew.get("tasks", {}).get(ph, {}).get("vulnerabilities", [])
        if vulns:
            return vulns[:3]
    return []


def memory_status(crew: dict, trace) -> str:
    # Prefer crew JSON top-level (pre-run shallow recall, reliable).
    # Fall back to trace research phase (LLM-reported, less reliable).
    hit = crew.get("memory_hit")
    if hit is None:
        hit = _phase_so(trace, "research").get("memory_hit")
    if hit is None:
        return "—"
    return "hit" if hit else "fresh"


def tool_stats(trace):
    """Return (total_calls, error_calls, [error_tool_names])."""
    if not trace:
        return 0, 0, []
    total = trace.get("total_tool_calls", 0)
    errors = trace.get("error_calls", 0)
    err_tools = []
    for pd in trace.get("phases", {}).values():
        for tc in pd.get("tool_calls", []):
            if tc.get("is_error"):
                err_tools.append(tc.get("tool_bin") or tc.get("tool_name") or "unknown")
    return total, errors, err_tools


# ── per-scan display ──────────────────────────────────────────────────────────

def print_scan(crew: dict, trace: dict | None, verbose: bool) -> None:
    target = crew.get("target", "?")
    scope = crew.get("scope", "?")
    pipeline = crew.get("pipeline", [])
    ts = crew.get("timestamp", "")

    dur = f"{trace['total_duration_s']:.1f}s" if trace else "—"
    ports = open_ports(trace)
    cvids = extract_cve_ids(cve_refs(trace))
    vulns = vulnerabilities(crew, trace)
    total_tc, err_tc, err_tools = tool_stats(trace)
    mem = memory_status(crew, trace)

    print("─" * WIDTH)
    print(f"SCAN:     {target} | {scope} | {dur}")
    print(f"DATE:     {fmt_ts(ts)}")
    print(f"PIPELINE: {' → '.join(pipeline)}")
    print(f"PORTS:    {', '.join(str(p) for p in ports) if ports else '—'}")
    print(f"CVEs:     {', '.join(cvids) if cvids else '—'}")

    if vulns:
        for i, v in enumerate(vulns):
            prefix = "FINDINGS: " if i == 0 else "          "
            print(f"{prefix}{truncate(str(v), WIDTH - 10)}")
    else:
        print("FINDINGS: —")

    if trace:
        tool_line = f"{total_tc} calls | {err_tc} errors"
        if err_tools:
            unique = list(dict.fromkeys(err_tools))
            tool_line += f" | errors: {', '.join(unique)}"
        print(f"TOOLS:    {tool_line}")
    else:
        print("TOOLS:    — (no trace file)")

    print(f"MEMORY:   {mem}")

    if verbose and trace:
        phases = trace.get("phases", {})
        for ph in pipeline:
            calls = phases.get(ph, {}).get("tool_calls", [])
            if not calls:
                continue
            print(f"\n  PHASE {ph}:")
            for tc in calls:
                seq = tc.get("seq", "?")
                cmd = truncate(fmt_command(tc.get("command", tc.get("tool_bin", "?"))), 46)
                dur_s = tc.get("duration_s", 0.0)
                if tc.get("is_error"):
                    status = error_reason(tc.get("raw_output", ""))
                else:
                    status = "ok"
                print(f"    [{seq:>2}] {cmd:<46}  {dur_s:>8.2f}s  {status}")


# ── Gesamtauswertung ──────────────────────────────────────────────────────────

def print_gesamtauswertung(scans: list) -> None:
    n = len(scans)
    if n == 0:
        return

    targets: set = set()
    cve_counter: Counter = Counter()
    port_counter: Counter = Counter()
    scope_counter: Counter = Counter()
    max_dur, max_target = 0.0, ""
    tool_err_counter: Counter = Counter()
    mem_hits = 0

    for crew, trace in scans:
        targets.add(crew.get("target", "?"))
        scope_counter[crew.get("scope", "?")] += 1

        if trace:
            d = trace.get("total_duration_s", 0.0)
            if d > max_dur:
                max_dur, max_target = d, crew.get("target", "?")

            for cid in extract_cve_ids(cve_refs(trace)):
                cve_counter[cid] += 1

            for p in open_ports(trace):
                port_counter[p] += 1

            for pd in trace.get("phases", {}).values():
                for tc in pd.get("tool_calls", []):
                    if tc.get("is_error"):
                        name = tc.get("tool_bin") or tc.get("tool_name") or "unknown"
                        tool_err_counter[name] += 1

            if memory_status(crew, trace) == "hit":
                mem_hits += 1

    top_cves = cve_counter.most_common(3)
    top_ports = port_counter.most_common(5)
    scope_str = " | ".join(f"{s}: {c}" for s, c in sorted(scope_counter.items()))
    longest = f"{max_target} ({max_dur:.1f}s)" if max_target else "—"
    err_tools_str = (
        ", ".join(f"{t}: {c}" for t, c in tool_err_counter.most_common(5))
        if tool_err_counter else "—"
    )

    print()
    print("GESAMTAUSWERTUNG")
    print("────────────────")
    print(f"Scans gesamt:             {n}")
    print(f"Targets:                  {', '.join(sorted(targets))}")
    print(f"Häufigste CVEs:           {', '.join(f'{c} (×{k})' for c, k in top_cves) if top_cves else '—'}")
    print(f"Häufigste Ports:          {', '.join(str(p) for p, _ in top_ports) if top_ports else '—'}")
    print(f"Scope-Verteilung:         {scope_str}")
    print(f"Längster Run:             {longest}")
    print(f"Fehleranfälligste Tools:  {err_tools_str}")
    print(f"Memory Hits:              {mem_hits} von {n}")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AgentScanIT scan log summarizer")
    parser.add_argument("--last", type=int, metavar="N", help="Show last N scans only")
    parser.add_argument("--verbose", action="store_true", help="Show per-phase tool-call details")
    args = parser.parse_args()

    crew_files = sorted(
        LOGS_DIR.glob("crew_*.json"),
        key=lambda p: p.stem[-15:],   # sort by embedded YYYYMMDD_HHMMSS
        reverse=True,
    )

    if not crew_files:
        print(f"No crew_*.json files found in {LOGS_DIR}", file=sys.stderr)
        sys.exit(1)

    if args.last:
        crew_files = crew_files[: args.last]

    scans = []
    for cf in crew_files:
        try:
            scans.append(load_pair(cf))
        except Exception as e:
            print(f"[WARN] {cf.name}: {e}", file=sys.stderr)

    for crew, trace in scans:
        print_scan(crew, trace, verbose=args.verbose)

    print("─" * WIDTH)
    print_gesamtauswertung(scans)


if __name__ == "__main__":
    main()
