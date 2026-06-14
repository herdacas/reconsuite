"""
quality.py — Deterministischer Scan-Quality-Scorer (Phase 8.1)

Liest trace_*.json + crew_*.json aus logs/ und berechnet einen Score
der die Qualität eines Scans objektiv misst — kein LLM, reine Datenauswertung.

Usage:
    from agentscanit.quality import score_scan, score_latest, print_scorecard
    report = score_scan("logs/trace_example.com_20260614_123456.json")
    print_scorecard(report)

CLI:
    python3 -m agentscanit.quality                    # neuester Scan
    python3 -m agentscanit.quality logs/trace_x.json  # konkreter Trace
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─── Gewichtung der Dimensionen ───────────────────────────────────────────────
# Summe = 100 Punkte

_WEIGHTS = {
    "phase_completeness": 25,   # Wurden alle erwarteten Phasen ausgeführt?
    "tool_coverage":      25,   # Wurden die Kern-Tools für den Scope gerufen?
    "cve_quality":        20,   # CVEs gefunden + tool-bestätigt?
    "error_rate":         15,   # Tool-Fehlerrate niedrig?
    "efficiency":         15,   # Laufzeit vs. Tool-Calls (kein Leerlauf)?
}

# Kern-Tools pro Scope (Minimum für volle tool_coverage-Punkte)
_SCOPE_CORE_TOOLS: dict[str, set[str]] = {
    "osint":   {"dig", "whois", "subfinder"},
    "quick":   {"nmap", "httpx"},
    "ssl":     {"sslscan"},
    "web":     {"httpx", "whatweb", "nikto"},
    "network": {"nmap", "httpx", "whatweb"},
    "full":    {"nmap", "httpx", "whatweb", "nikto", "sslscan", "subfinder"},
}

# Erwartete Phasen pro Scope
_SCOPE_PHASES: dict[str, list[str]] = {
    "osint":   ["research", "report"],
    "quick":   ["research", "blue", "findings", "report"],
    "ssl":     ["research", "blue", "report"],
    "web":     ["research", "blue", "findings", "red", "report"],
    "network": ["research", "blue", "findings", "red", "report"],
    "full":    ["research", "blue", "findings", "red", "report"],
}


@dataclass
class DimensionScore:
    name: str
    score: float        # 0–100 innerhalb der Dimension
    weight: float       # Gewichtung (0–100, Summe aller = 100)
    weighted: float     # score * weight / 100
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanQualityReport:
    target: str
    scope: str
    trace_path: str
    total_score: float          # 0–100
    grade: str                  # A / B / C / D / F
    dimensions: list[DimensionScore]
    scan_duration_s: float
    total_tool_calls: int
    error_calls: int
    phases_run: list[str]
    cve_count: int
    timestamp: str = ""

    @property
    def grade_color(self) -> str:
        return {
            "A": "bold green", "B": "green",
            "C": "yellow", "D": "red", "F": "bold red",
        }.get(self.grade, "white")


def _grade(score: float) -> str:
    if score >= 85:  return "A"
    if score >= 70:  return "B"
    if score >= 55:  return "C"
    if score >= 40:  return "D"
    return "F"


def _all_tool_names(trace: dict) -> set[str]:
    """Alle aufgerufenen Tool-Namen über alle Phasen."""
    names: set[str] = set()
    for phase_data in trace.get("phases", {}).values():
        for call in phase_data.get("tool_calls", []):
            name = call.get("tool_name") or call.get("tool_bin") or ""
            if name:
                # Normalisiere: 'nvd_cpe_lookup' → 'nvd_cpe_lookup', 'nmap_scanner' → 'nmap' etc.
                names.add(name)
                # Auch Kurzname (vor erstem '_') hinzufügen für flexible Matching
                short = name.split("_")[0]
                if short:
                    names.add(short)
    return names


def _score_phase_completeness(trace: dict, scope: str) -> DimensionScore:
    expected = _SCOPE_PHASES.get(scope, ["research", "blue", "findings", "report"])
    phases_run = [
        p for p, d in trace.get("phases", {}).items()
        if d.get("tool_calls") or d.get("structured_output")
    ]
    notes = []
    missing = [p for p in expected if p not in phases_run]
    if missing:
        notes.append(f"Fehlende Phasen: {missing}")
    present = [p for p in expected if p in phases_run]
    ratio = len(present) / max(len(expected), 1)
    score = ratio * 100
    # Bonus: red-Phase mit Findings
    if "red" in phases_run:
        red_out = trace.get("phases", {}).get("red", {}).get("structured_output") or {}
        if red_out.get("confirmed_attack_surface"):
            notes.append(f"red-Phase: {len(red_out['confirmed_attack_surface'])} bestätigte Angriffsvektoren")
    return DimensionScore(
        name="Phase-Vollständigkeit",
        score=round(score, 1),
        weight=_WEIGHTS["phase_completeness"],
        weighted=round(score * _WEIGHTS["phase_completeness"] / 100, 1),
        notes=notes,
    )


def _score_tool_coverage(trace: dict, scope: str) -> DimensionScore:
    required = _SCOPE_CORE_TOOLS.get(scope, set())
    if not required:
        return DimensionScore("Tool-Coverage", 100, _WEIGHTS["tool_coverage"],
                              _WEIGHTS["tool_coverage"], ["Kein Scope-Mapping — 100% angenommen"])
    used = _all_tool_names(trace)
    notes = []
    hit = set()
    for req in required:
        # Flexible Matching: 'nmap' matcht 'nmap_scanner', 'nmap' etc.
        if any(req in u or u in req for u in used):
            hit.add(req)
    missing = required - hit
    if missing:
        notes.append(f"Kern-Tools nicht aufgerufen: {sorted(missing)}")
    # Bonus: zusätzliche Tools über das Minimum hinaus
    extra_tools = {u for u in used if u not in {"unknown", ""}} - required
    if extra_tools:
        notes.append(f"Zusätzliche Tools: {len(extra_tools)} ({', '.join(sorted(extra_tools)[:5])}{'…' if len(extra_tools) > 5 else ''})")
    ratio = len(hit) / max(len(required), 1)
    # Bonus bis 10 Punkte für breite Coverage
    bonus = min(10, len(extra_tools) * 2) if ratio == 1.0 else 0
    score = min(100, ratio * 90 + bonus)
    return DimensionScore(
        name="Tool-Coverage",
        score=round(score, 1),
        weight=_WEIGHTS["tool_coverage"],
        weighted=round(score * _WEIGHTS["tool_coverage"] / 100, 1),
        notes=notes,
    )


def _score_cve_quality(trace: dict) -> DimensionScore:
    notes = []
    # CVEs aus findings + red zusammenzählen
    phases = trace.get("phases", {})
    findings_out = phases.get("findings", {}).get("structured_output") or {}
    red_out      = phases.get("red", {}).get("structured_output") or {}
    cve_findings = findings_out.get("cve_references", [])
    cve_red      = red_out.get("cve_references", [])
    all_cves = list(dict.fromkeys(cve_findings + cve_red))
    cve_count = len(all_cves)

    # CVEs im Trace-Raw-Output (tool-bestätigt)
    all_raw = " ".join(
        c.get("raw_output", "")
        for p in phases.values()
        for c in p.get("tool_calls", [])
    )
    import re as _re
    raw_cves = set(_re.findall(r'CVE-\d{4}-\d{4,7}', all_raw))

    if cve_count == 0:
        # Kein CVE: prüfe ob CVEs im Trace vorhanden aber nicht extrahiert
        if raw_cves:
            notes.append(f"CVEs in Tool-Output aber nicht extrahiert: {len(raw_cves)} ({', '.join(sorted(raw_cves)[:3])}…)")
            score = 20.0
        else:
            notes.append("Keine CVEs gefunden (Target möglicherweise sauber oder Scope zu eng)")
            score = 50.0  # neutral — kein Befund ≠ schlechter Scan
    else:
        # Wie viele der extrahierten CVEs sind tool-bestätigt?
        confirmed = [c for c in all_cves if c in raw_cves]
        ratio = len(confirmed) / max(cve_count, 1)
        if ratio < 1.0:
            hallucinated = [c for c in all_cves if c not in raw_cves]
            notes.append(f"Mögliche Halluzinationen: {hallucinated}")
        notes.append(f"{cve_count} CVEs extrahiert, {len(confirmed)} tool-bestätigt")
        # Score: bestätigte CVEs zählen, Halluzinationen bestrafen
        score = min(100, len(confirmed) * 15 + (ratio * 30))

    # Bonus: nvd_cpe_lookup verwendet (CPE-first Architektur)
    if any("nvd_cpe_lookup" in (c.get("tool_name","") or "") or "nvd_cpe" in (c.get("tool_bin","") or "")
           for p in phases.values() for c in p.get("tool_calls",[])):
        notes.append("nvd_cpe_lookup verwendet (CPE-first)")
        score = min(100, score + 10)

    return DimensionScore(
        name="CVE-Qualität",
        score=round(score, 1),
        weight=_WEIGHTS["cve_quality"],
        weighted=round(score * _WEIGHTS["cve_quality"] / 100, 1),
        notes=notes,
    )


def _score_error_rate(trace: dict) -> DimensionScore:
    total = trace.get("total_tool_calls", 0)
    errors = trace.get("error_calls", 0)
    notes = []
    if total == 0:
        return DimensionScore("Fehlerrate", 0, _WEIGHTS["error_rate"],
                              0, ["Keine Tool-Calls — Scan hat nicht gestartet"])
    rate = errors / total
    score = max(0, 100 - rate * 200)   # 0 errors=100, 50% errors=0
    if errors > 0:
        # Welche Tools haben Fehler?
        error_tools = [
            c.get("tool_name") or c.get("tool_bin", "?")
            for p in trace.get("phases", {}).values()
            for c in p.get("tool_calls", [])
            if c.get("is_error")
        ]
        notes.append(f"{errors}/{total} Tool-Calls mit [TOOL_ERROR]: {set(error_tools)}")
    else:
        notes.append(f"0/{total} Fehler")
    return DimensionScore(
        name="Fehlerrate",
        score=round(score, 1),
        weight=_WEIGHTS["error_rate"],
        weighted=round(score * _WEIGHTS["error_rate"] / 100, 1),
        notes=notes,
    )


def _score_efficiency(trace: dict) -> DimensionScore:
    duration = trace.get("total_duration_s", 0)
    total    = trace.get("total_tool_calls", 0)
    scope    = trace.get("scope", "full")
    notes = []

    if total == 0 or duration == 0:
        return DimensionScore("Effizienz", 0, _WEIGHTS["efficiency"],
                              0, ["Keine Daten"])

    # Erwartete Laufzeit-Bandbreite pro Scope (Sekunden)
    _EXPECTED = {
        "osint":   (30,  180),
        "quick":   (30,  120),
        "ssl":     (20,   90),
        "web":     (60,  300),
        "network": (120, 600),
        "full":    (180, 900),
    }
    lo, hi = _EXPECTED.get(scope, (60, 600))

    if duration < lo:
        notes.append(f"Sehr schnell ({duration}s < {lo}s erwartet) — möglicherweise Phasen übersprungen")
        score = 60.0
    elif duration <= hi:
        # Optimal
        score = 100.0
        notes.append(f"Laufzeit {duration}s im erwarteten Bereich ({lo}–{hi}s)")
    else:
        # Zu langsam
        overshoot = (duration - hi) / hi
        score = max(20, 100 - overshoot * 50)
        notes.append(f"Laufzeit {duration}s überschreitet Erwartung {hi}s um {round(overshoot*100)}%")

    # Calls pro Minute
    calls_per_min = round(total / (duration / 60), 1)
    notes.append(f"{total} Tool-Calls in {duration}s ({calls_per_min}/min)")

    return DimensionScore(
        name="Effizienz",
        score=round(score, 1),
        weight=_WEIGHTS["efficiency"],
        weighted=round(score * _WEIGHTS["efficiency"] / 100, 1),
        notes=notes,
    )


def score_scan(trace_path: str) -> ScanQualityReport:
    """Berechnet den Quality-Score für einen Scan anhand seiner trace_*.json Datei."""
    with open(trace_path) as f:
        trace = json.load(f)

    scope  = trace.get("scope", "full")
    target = trace.get("target", "?")

    dims = [
        _score_phase_completeness(trace, scope),
        _score_tool_coverage(trace, scope),
        _score_cve_quality(trace),
        _score_error_rate(trace),
        _score_efficiency(trace),
    ]

    total = round(sum(d.weighted for d in dims), 1)
    phases_run = [
        p for p, d in trace.get("phases", {}).items()
        if d.get("tool_calls") or d.get("structured_output")
    ]
    findings_out = trace.get("phases", {}).get("findings", {}).get("structured_output") or {}
    red_out      = trace.get("phases", {}).get("red", {}).get("structured_output") or {}
    cve_count = len(set(
        findings_out.get("cve_references", []) + red_out.get("cve_references", [])
    ))

    return ScanQualityReport(
        target=target,
        scope=scope,
        trace_path=trace_path,
        total_score=total,
        grade=_grade(total),
        dimensions=dims,
        scan_duration_s=trace.get("total_duration_s", 0),
        total_tool_calls=trace.get("total_tool_calls", 0),
        error_calls=trace.get("error_calls", 0),
        phases_run=phases_run,
        cve_count=cve_count,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


def score_latest(log_dir: str = "logs") -> Optional[ScanQualityReport]:
    """Score des neuesten Scans in log_dir."""
    traces = sorted(
        [f for f in os.listdir(log_dir) if f.startswith("trace_") and f.endswith(".json")],
        reverse=True,
    )
    if not traces:
        return None
    return score_scan(os.path.join(log_dir, traces[0]))


def print_scorecard(report: ScanQualityReport) -> None:
    """Gibt den Scorecard als Rich-formatierte Tabelle aus."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        con = Console()
    except ImportError:
        # Fallback ohne Rich
        print(f"\n=== Scan Quality Score: {report.target} ({report.scope}) ===")
        print(f"Total: {report.total_score}/100  Grade: {report.grade}")
        for d in report.dimensions:
            print(f"  {d.name}: {d.score:.0f}/100 (gewichtet: {d.weighted:.1f})")
            for n in d.notes:
                print(f"    · {n}")
        return

    # Header
    con.print()
    con.print(Panel(
        f"[bold]{report.target}[/]  ·  scope=[cyan]{report.scope}[/]  "
        f"·  {report.total_tool_calls} Tool-Calls  ·  {report.scan_duration_s}s  "
        f"·  {report.cve_count} CVEs",
        title="[bold]Scan Quality Scorecard[/]",
        subtitle=f"[dim]{report.trace_path}[/]",
    ))

    # Score-Tabelle
    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Dimension",       style="bold",  width=24)
    table.add_column("Score",           justify="right", width=8)
    table.add_column("Gewichtet",       justify="right", width=10)
    table.add_column("Notizen",         width=55)

    for d in report.dimensions:
        color = "green" if d.score >= 70 else "yellow" if d.score >= 45 else "red"
        table.add_row(
            d.name,
            f"[{color}]{d.score:.0f}/100[/]",
            f"{d.weighted:.1f}",
            "  ".join(d.notes[:2]),
        )

    con.print(table)

    # Gesamt-Score
    grade_color = report.grade_color
    con.print(
        f"\n  Gesamt-Score: [{grade_color}]{report.total_score}/100  "
        f"Grade {report.grade}[/]  "
        f"[dim]({report.timestamp})[/]"
    )
    con.print()


if __name__ == "__main__":
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    if len(sys.argv) > 1:
        trace_path = sys.argv[1]
    else:
        traces = sorted(
            [f for f in os.listdir(log_dir) if f.startswith("trace_") and f.endswith(".json")],
            reverse=True,
        )
        if not traces:
            print("Keine trace_*.json Dateien in logs/")
            sys.exit(1)
        trace_path = os.path.join(log_dir, traces[0])
    report = score_scan(trace_path)
    print_scorecard(report)
