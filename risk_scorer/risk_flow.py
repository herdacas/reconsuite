"""
risk_scorer/risk_flow.py — Team 6: Asset Risk Scorer

Aggregiert alle Team-Outputs zu einem priorisierten Risk-Score.
Keine Agents — reine Berechnung auf Basis strukturierter Daten.

Formel:
    base_score  = max(CVSS-Score aller CVEs, 0)
    exploit_mul = 1.3 wenn confirmed_attack_surface nicht leer, sonst 1.0
    threat_mul  = 1.2 wenn in-the-wild CVEs, sonst 1.0
    risk_score  = min(base_score × exploit_mul × threat_mul, 10.0)

Eingabe:
  - workflow_last.json          (Scan-Ergebnisse Team 1)
  - logs/interpret_*.md         (NVD-Daten Team 2, optional)
  - state.threat_intel_output   (Threat-Intel Summary Team 4)
  - state.compliance_output     (Compliance-Report Team 5)
Ausgabe:
  - logs/risk_score_<target>_<ts>.md
  - logs/risk_score_<target>_<ts>.json
"""

import json
import os
import re
import sys
from datetime import datetime

from pydantic import BaseModel, Field
from crewai.flow.flow import Flow, start, listen
from rich.console import Console
from rich.panel import Panel

_TEAM_DIR  = os.path.dirname(os.path.abspath(__file__))
_SUITE_DIR = os.path.dirname(_TEAM_DIR)
LOG_DIR    = os.path.join(_SUITE_DIR, "logs")

if _SUITE_DIR not in sys.path:
    sys.path.insert(0, _SUITE_DIR)
import cve_filters  # Shared Versions-Gate-Filterung (auch von reporting_flow genutzt)

console = Console()


# ─── State ────────────────────────────────────────────────────────────────────

class RiskState(BaseModel):
    scan_json_path:      str        = ""
    scan_target:         str        = ""
    scan_body:           str        = ""   # recon_report_*.md-Body, für Versions-Gate (cve_filters)
    nvd_results:         list[dict] = Field(default_factory=list)
    threat_intel_output: str        = ""   # aus ScanState
    compliance_output:   str        = ""   # aus ScanState
    has_exploitable:     bool       = False
    # PoC-verifiziert (2026-09-19, Output-Qualitäts-Fix Punkt 5): getrennt von
    # has_exploitable, das lediglich "irgendeine CVE beim red-Task gefunden"
    # bedeutet (has_exploitable=True kann schon durch nicht-leere red_cves
    # gesetzt sein, siehe flow.py route_results()). poc_verified misst dagegen
    # ob RedOutput.exploitable_findings selbst nicht leer ist — das strengere,
    # PoC-belegte Feld. Live gefunden (pentest-ground.com-Scan): "Exploitable:
    # ✓ Ja" stand im Report obwohl exploitable_findings komplett leer war —
    # zweideutiges Label, suggerierte PoC-Bestätigung die es nicht gab.
    poc_verified:        bool       = False
    risk_score:          float      = 0.0
    risk_level:          str        = "NONE"
    critical_count:      int        = 0
    high_count:          int        = 0
    top_findings:        list[dict] = Field(default_factory=list)
    report_md_path:      str        = ""
    report_json_path:    str        = ""


# ─── Flow ─────────────────────────────────────────────────────────────────────

class RiskFlow(Flow[RiskState]):
    """Asset Risk Scoring — keine Agents, deterministische Berechnung."""

    @start()
    def load_data(self):
        path = self.state.scan_json_path or os.path.join(LOG_DIR, "workflow_last.json")

        try:
            with open(path) as f:
                summary = json.load(f)
        except Exception as e:
            console.print(f"  [red]✗[/]  RiskFlow: {e}")
            return

        self.state.scan_target = summary.get("target", "unknown")
        # Scan-Body für die Versions-Gate-Filterung (BUG-Backlog 2026-09-11:
        # Critical-Count-Inkonsistenz — muss dieselbe Basis wie reporting_flow nutzen).
        self.state.scan_body = cve_filters.load_scan_body(summary.get("report", ""))

        # CVEs + CVSS aus Tasks extrahieren
        cves: list[dict] = []
        for task_data in summary.get("tasks", {}).values():
            for cve_id in task_data.get("cve_references", []):
                if not any(c["id"] == cve_id for c in cves):
                    cves.append({"id": cve_id, "cvss": None, "severity": "UNKNOWN"})
            # BUG gefunden bei der Live-Verifikation (2026-09-19, scanme.nmap.org):
            # workflow_last.json/crew_*.json speichert laut agentscanit/main.py
            # NIE die volle 'exploitable_findings'-Liste, nur 'exploitable_findings_
            # count' (Integer) — der ursprüngliche Check auf den nie vorhandenen
            # Listen-Key war für has_exploitable schon immer toter Code (maskiert,
            # da has_exploitable meist schon über den extern übergebenen Parameter
            # gesetzt war) und hätte poc_verified NIE True werden lassen.
            if task_data.get("exploitable_findings_count", 0) > 0:
                self.state.has_exploitable = True
                self.state.poc_verified = True

        # CVSS aus NVD-Ergebnissen anreichern (falls vorhanden)
        for nvd in self.state.nvd_results:
            cve_id = nvd.get("id", "")
            for cve in cves:
                if cve["id"] == cve_id:
                    cve["cvss"]     = nvd.get("cvss_score")
                    cve["severity"] = nvd.get("cvss_severity", "UNKNOWN")

        self.state.top_findings = cves

        console.print()
        console.print(Panel(
            f"[bold blue]risk-scorer[/]  ·  Asset Risk Scoring\n\n"
            f"  [dim]Target:[/]     [bold white]{self.state.scan_target}[/]\n"
            f"  [dim]CVEs:[/]       {len(cves)}\n"
            f"  [dim]CVE-Treffer:[/] {'ja' if self.state.has_exploitable else 'nein'}   "
            f"[dim]PoC-verifiziert:[/] {'ja' if self.state.poc_verified else 'nein'}",
            border_style="blue", expand=False, padding=(0, 2),
        ))

    @listen(load_data)
    def calculate_score(self):
        cves     = self.state.top_findings
        nvd_data = self.state.nvd_results

        # Zähler + Score-Basis — dieselbe Versions-Gate-Filterung wie reporting_flow
        # (cve_filters.py), damit "Critical: N" in Risk Score und Final Report garantiert
        # übereinstimmen (Backlog-Fix 2026-09-11: vorher zählte risk_flow direkt aus dem
        # ungefilterten nvd_results, reporting_flow nur version-bestätigte + KEV-CVEs —
        # zwei Zahlen für denselben Scan).
        counted = cve_filters.counted_cves(nvd_data, self.state.scan_body)
        counted_ids = {c["id"] for c in counted}
        self.state.critical_count, self.state.high_count = cve_filters.severity_counts(counted)

        # Basis: höchster CVSS-Score — NUR unter den Versions-Gate-bestätigten CVEs.
        # Sonst widerspräche sich der Report selbst: "Critical: 0 / High: 0" bei
        # gleichzeitig CRITICAL-Score, getrieben von einer CVE die laut derselben
        # Versions-Gate-Filterung gar nicht als bestätigt zählt (live beobachtet am
        # example.com-Scan 2026-09-12: CVE-2019-0190 versionslos/unbestätigt, trotzdem
        # Score 9.8 CRITICAL vor diesem Fix).
        counted_scores = [c["cvss_score"] for c in counted if c.get("cvss_score") is not None]
        base_score = max(counted_scores) if counted_scores else (5.0 if counted else 0.0)

        # Multiplikatoren
        exploit_mul = 1.3 if self.state.has_exploitable else 1.0
        threat_mul  = 1.2 if _has_in_the_wild(self.state.threat_intel_output) else 1.0

        raw_score = base_score * exploit_mul * threat_mul
        self.state.risk_score = round(min(raw_score, 10.0), 1)
        self.state.risk_level = _score_to_level(self.state.risk_score)

        console.print(
            f"  [green]✓[/]  Risk Score: [bold]{self.state.risk_score}[/] "
            f"([bold]{self.state.risk_level}[/])  "
            f"[dim]base={base_score:.1f} × exploit={exploit_mul} × threat={threat_mul}[/]"
        )

    @listen(calculate_score)
    def write_report(self):
        target   = self.state.scan_target
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe     = re.sub(r"[^\w.-]", "_", target)
        level    = self.state.risk_level
        score    = self.state.risk_score

        level_color = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢", "NONE": "⚪",
        }.get(level, "⚪")

        md_lines = [
            f"**Target:** {target}  ",
            f"**Date:** {ts_human}  \n",
            "---\n",
            f"# Asset Risk Score: {target}\n",
            f"## {level_color} Risk Score: {score} / 10 — {level}\n",
            "## Metrics\n",
            f"| Metric | Value |",
            "|---|---|",
            f"| Risk Score | **{score}** |",
            f"| Risk Level | **{level}** |",
            f"| Critical CVEs | {self.state.critical_count} |",
            f"| High CVEs | {self.state.high_count} |",
            f"| CVE-Treffer (red-Task) | {'✓ Ja' if self.state.has_exploitable else '✗ Nein'} |",
            f"| PoC-verifiziert | {'✓ Ja' if self.state.poc_verified else '✗ Nein'} |",
            f"| In-the-Wild | {'✓ Ja' if _has_in_the_wild(self.state.threat_intel_output) else '✗ Nein / unbekannt'} |\n",
        ]

        if self.state.top_findings:
            # Welche CVE-IDs zählen laut Versions-Gate als bestätigt (dieselbe Basis wie
            # critical_count/high_count/base_score oben) — Top Findings zeigt weiterhin
            # ALLE referenzierten CVEs (nichts wird versteckt), aber unbestätigte werden
            # explizit markiert statt unkommentiert neben bestätigten zu stehen.
            counted_ids = {
                c["id"] for c in cve_filters.counted_cves(self.state.nvd_results, self.state.scan_body)
            }
            md_lines += ["## Top Findings\n"]
            sorted_cves = sorted(
                self.state.top_findings,
                key=lambda c: c.get("cvss") or 0,
                reverse=True,
            )
            for cve in sorted_cves[:10]:
                sev   = (cve.get("severity") or "UNKNOWN").upper()
                cvss  = cve.get("cvss")
                score_str = f"CVSS {cvss}" if cvss is not None else "CVSS N/A"
                tag = "" if cve["id"] in counted_ids else "  ⚠️ *unbestätigt — keine Versions-Bestätigung*"
                md_lines.append(f"- **{cve['id']}** — {score_str} ({sev}){tag}")
            md_lines.append("")

        md_lines += [
            "## Recommended Next Steps\n",
            *_next_steps(self.state),
        ]

        md_path = os.path.join(LOG_DIR, f"risk_score_{safe}_{ts}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))
        self.state.report_md_path = md_path

        # JSON-Output für maschinelle Weiterverarbeitung
        counted_ids = {
            c["id"] for c in cve_filters.counted_cves(self.state.nvd_results, self.state.scan_body)
        }
        top_findings_json = [
            {**c, "version_confirmed": c["id"] in counted_ids}
            for c in self.state.top_findings[:10]
        ]
        json_data = {
            "target":          target,
            "timestamp":       ts_human,
            "risk_score":      self.state.risk_score,
            "risk_level":      self.state.risk_level,
            "critical_count":  self.state.critical_count,
            "high_count":      self.state.high_count,
            "exploitable":     self.state.has_exploitable,
            "poc_verified":    self.state.poc_verified,
            "in_the_wild":     _has_in_the_wild(self.state.threat_intel_output),
            "top_findings":    top_findings_json,
        }
        json_path = os.path.join(LOG_DIR, f"risk_score_{safe}_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        self.state.report_json_path = json_path

        console.print(f"  [dim]Risk Score → {md_path}[/]")
        console.print(f"  [dim]Risk JSON  → {json_path}[/]")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _has_in_the_wild(threat_output: str) -> bool:
    """Heuristik: prüft ob Threat-Intel-Report aktive Exploitation enthält.

    Achtung: threat_summary enthält immer "CVEs in-the-wild: N / M" —
    ein simpler Substring-Match auf "in-the-wild" würde immer True liefern.
    Deshalb: nur spezifische positive Indikatoren suchen, nie den neutralen
    Counter-String selbst.
    """
    if not threat_output:
        return False
    lower = threat_output.lower()
    return any(kw in lower for kw in [
        "aktiv in-the-wild",   # OTX: "aktiv in-the-wild" (vs. neutralem "in-the-wild: 0/5")
        "aktiv ausgenutzt",
        "has_exploit: true",
        "🔴",                  # nur gesetzt wenn in_wild=True in threatintel_flow.py:169
    ])


def _score_to_level(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _next_steps(state: RiskState) -> list[str]:
    """Pentest-Scope (2026-06-25): Priorisierung der ANGRIFFS-Schritte für den
    Pentester — NICHT defensive Härtungs-/Patch-Empfehlungen. Deterministisch.
    Remediation gehört nur in den Report wenn die Ausnutzbarkeit nachgewiesen ist
    (das übernimmt das compliance-Team mit der nuclei-PoC-Schranke), nicht hier.
    """
    steps = []
    if state.has_exploitable:
        steps.append("- **Priorisierte Angriffsvektoren:** Die als ausnutzbar identifizierten "
                     "Dienste zuerst angehen — Exploit entwickeln/anpassen und Zugang verifizieren.")
    if _has_in_the_wild(state.threat_intel_output):
        steps.append("- **Aktiv ausgenutzt (in-the-wild):** Für diese CVEs existieren reale "
                     "Exploits — öffentliche PoCs als Ausgangsbasis für die Ausnutzung prüfen.")
    if state.critical_count > 0:
        steps.append(f"- **{state.critical_count} Critical CVE(s):** Höchste Priorität für "
                     "Exploit-Entwicklung — potenzieller Vollzugriff/RCE.")
    if state.high_count > 0:
        steps.append(f"- **{state.high_count} High CVE(s):** Sekundäre Angriffsziele — "
                     "auf Verkettbarkeit mit den Critical-Vektoren prüfen.")
    if not steps:
        steps.append("- Keine ausnutzbaren Vektoren in dieser Session bestätigt. "
                     "Weitere Recon empfohlen (tiefere Enumeration, Subdomains, andere Ports).")
    return steps


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_risk_flow(
    scan_json_path: str = "",
    nvd_results: list[dict] | None = None,
    threat_intel_output: str = "",
    compliance_output: str = "",
    has_exploitable: bool = False,
) -> RiskFlow:
    flow = RiskFlow()
    flow.state.scan_json_path      = scan_json_path
    flow.state.nvd_results         = nvd_results or []
    flow.state.threat_intel_output = threat_intel_output
    flow.state.compliance_output   = compliance_output
    flow.state.has_exploitable     = has_exploitable
    flow.kickoff()
    return flow


if __name__ == "__main__":
    import sys as _sys
    run_risk_flow(_sys.argv[1] if len(_sys.argv) > 1 else "")
