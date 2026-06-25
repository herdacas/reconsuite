#!/usr/bin/env python3
"""
eval_tool_output.py — Dimension 2: Tool-Output-Handling

Prüft DETERMINISTISCH, ob der Agent die Tool-Ergebnisse korrekt übernahm:
  - Keine Halluzination: jede CVE in den strukturierten Agent-Outputs (crew_*.json:
    findings/red cve_references) muss in einem raw_output eines Tool-Calls vorkommen.
    (Identische Logik wie tools/trace.py::cve_in_raw_outputs — Substring-Match.)
  - Keine Port-Auslassung: offene Ports die nmap im raw_output meldete, sollen im
    strukturierten blue-Output erscheinen.

Read-only. Braucht den trace_*.json (raw_outputs) UND optional crew_*.json
(strukturierte Agent-Outputs). Wenn kein crew_*.json: fällt auf CVE-Regex im Report zurück.

Verwendung:
    python3 eval_tool_output.py logs/trace_<t>_<ts>.json [logs/crew_<t>_<ts>.json]
"""
from __future__ import annotations
import json
import re
import sys
from dataclasses import dataclass, field

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_PORT_RE = re.compile(r"\b(\d{1,5})/tcp\s+open\b")


@dataclass
class OutputEvalResult:
    trace_path: str
    hallucinated_cves: list[str] = field(default_factory=list)
    confirmed_cves: list[str] = field(default_factory=list)
    omitted_ports: list[int] = field(default_factory=list)

    @property
    def hallucination_count(self) -> int:
        return len(self.hallucinated_cves)

    @property
    def passed(self) -> bool:
        # Halluzinationen sind hart verboten. Port-Auslassung ist ein Warn-Signal,
        # kein harter Fail (nmap meldet teils gefilterte/irrelevante Ports).
        return self.hallucination_count == 0


def _all_raw_output(trace: dict) -> str:
    return " ".join(
        c.get("raw_output", "") or ""
        for p in trace.get("phases", {}).values()
        for c in p.get("tool_calls", [])
    )


def _structured_cves(crew: dict | None, report_text: str | None) -> set[str]:
    """CVE-IDs aus den strukturierten Agent-Outputs (bevorzugt) oder Report-Fallback."""
    if crew:
        cves: set[str] = set()
        for task in ("findings", "red"):
            cves |= {c.upper() for c in crew.get("tasks", {}).get(task, {}).get("cve_references", [])}
        if cves:
            return cves
    # Fallback: Report-Text
    if report_text:
        return {m.upper() for m in _CVE_RE.findall(report_text)}
    return set()


def evaluate_tool_output(trace_path: str, crew_path: str | None = None,
                         report_text: str | None = None) -> OutputEvalResult:
    trace = json.load(open(trace_path))
    crew = json.load(open(crew_path)) if crew_path else None
    res = OutputEvalResult(trace_path=trace_path)

    raw = _all_raw_output(trace)
    raw_cves = {m.upper() for m in _CVE_RE.findall(raw)}

    # 1) Halluzinations-Check
    structured = _structured_cves(crew, report_text)
    for cve in sorted(structured):
        if cve in raw_cves:
            res.confirmed_cves.append(cve)
        else:
            res.hallucinated_cves.append(cve)

    # 2) Port-Auslassung: Ports aus nmap-raw_output vs. strukturierter blue-Output
    nmap_ports = set()
    for p in trace.get("phases", {}).values():
        for c in p.get("tool_calls", []):
            if "nmap" in (c.get("tool_name", "") or ""):
                nmap_ports |= {int(m) for m in _PORT_RE.findall(c.get("raw_output", "") or "")}
    if crew and nmap_ports:
        blue_ports = set(crew.get("tasks", {}).get("blue", {}).get("open_ports", []) or [])
        # nur melden wenn der blue-Output Ports überhaupt strukturiert hat
        if blue_ports:
            res.omitted_ports = sorted(nmap_ports - blue_ports)

    return res


def print_result(res: OutputEvalResult) -> None:
    print(f"=== Dim 2: Tool-Output — {res.trace_path.split('/')[-1]} ===")
    print(f"  CVEs: {len(res.confirmed_cves)} tool-bestätigt, "
          f"{res.hallucination_count} HALLUZINIERT  "
          f"{'PASS' if res.passed else 'FAIL'}")
    if res.hallucinated_cves:
        print(f"  ⚠️ Halluzinierte CVEs (in keinem Tool-Output): {res.hallucinated_cves}")
    if res.omitted_ports:
        print(f"  ⚠️ Ports von nmap nicht im strukturierten Output: {res.omitted_ports}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: eval_tool_output.py <trace.json> [<crew.json>]")
        sys.exit(2)
    crew = sys.argv[2] if len(sys.argv) > 2 else None
    r = evaluate_tool_output(sys.argv[1], crew)
    print_result(r)
    sys.exit(0 if r.passed else 1)
