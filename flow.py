"""
recon-suite/flow.py — Master-Flow

Orchestriert alle Teams sequentiell:
    1. agentscanit       → Active Recon & Enumeration
    2. interpret-agent   → CVE Enrichment (NVD API v2)
    3. threatintel_agent → Threat Intelligence (OTX, Shodan, VT)
    4. compliance_agent  → Compliance Mapping (OWASP, CIS)
    5. risk_scorer       → Asset Risk Scoring
    6. reporting         → Final Report (Merge)

Routing nach dem Scan:
    full_analysis → interpret + threat_intel + compliance + risk + reporting
    cve_analysis  → interpret + compliance + risk + reporting
    clean         → nur reporting (kein NVD-Lookup nötig)

Usage:
    python3 flow.py example.com "full assessment" full
    from flow import run_flow, resume_flow
"""

import sys
import os
import json
from uuid import uuid4

# ── Teams registrieren ─────────────────────────────────────────────────────────
_SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SUITE_DIR)

import agentscanit.main as _scan_main       # lädt CrewAI-Patches als Seiteneffekt
from agentscanit import AgentScanITCrew
import interpret_agent as _interpret        # Team 2: NVD-Enrichment
import reporting as _reporting             # Team 3: Final Report
import threatintel_agent as _threatintel   # Team 4: Threat Intelligence
import compliance_agent as _compliance     # Team 5: Compliance Mapper
import risk_scorer as _risk                # Team 6: Risk Scorer

from pydantic import BaseModel, Field
from crewai.flow.flow import Flow, start, listen, router, or_
from crewai.flow.persistence import persist, SQLiteFlowPersistence
from rich.console import Console
from rich.prompt import Prompt

LOG_DIR = os.path.join(_SUITE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_FLOW_DB = os.path.join(LOG_DIR, "flow_state.db")

console = Console()


# ─── State ────────────────────────────────────────────────────────────────────

class ScanState(BaseModel):
    id:                   str        = Field(default_factory=lambda: str(uuid4()))
    target:               str        = ""
    objective:            str        = ""
    scope:                str        = "full"
    pipeline:             list[str]  = Field(default_factory=list)
    has_cve_findings:     bool       = False
    has_exploitable:      bool       = False
    scan_report_path:     str        = ""
    scan_json_path:       str        = ""
    nvd_results:          list[dict] = Field(default_factory=list)
    final_report_path:    str        = ""
    # Phase 7 — neue Team-Outputs
    threat_intel_output:  str        = ""
    compliance_output:    str        = ""
    risk_score_output:    str        = ""
    # Resume-Tracking (Phase 7, Stufe 3 Vorstufe): abgeschlossene Flow-Schritte.
    # Wird via @persist mitserialisiert; bei --resume (restore_from_state_id)
    # hydratisiert → erledigte Schritte werden übersprungen statt neu ausgeführt.
    completed_steps:      list[str]  = Field(default_factory=list)


# ─── Flow ─────────────────────────────────────────────────────────────────────

@persist(SQLiteFlowPersistence(_FLOW_DB), verbose=False)
class ReconSuiteFlow(Flow[ScanState]):
    """Master-Flow: agentscanit → interpret-agent → reporting."""

    # ─── Resume-Skip-Guards ────────────────────────────────────────────────
    # @persist restored bei --resume den State, führt die @listen-Methoden aber
    # von vorn aus. Ohne Guard würde run_scan etc. die (teure) Arbeit erneut tun.
    # _step_done() überspringt einen Schritt der laut completed_steps schon lief.
    def _step_done(self, name: str) -> bool:
        if name in self.state.completed_steps:
            console.print(f"  [dim]↻ {name} übersprungen (Resume — bereits abgeschlossen)[/]")
            return True
        return False

    def _mark_step(self, name: str) -> None:
        if name not in self.state.completed_steps:
            self.state.completed_steps.append(name)

    @start()
    def initialize(self):
        scanner = AgentScanITCrew(
            self.state.target,
            self.state.objective,
            self.state.scope,
        )
        self.state.target    = scanner.target
        self.state.objective = scanner.objective
        self.state.scope     = scanner.scope

    @listen(initialize)
    def run_scan(self):
        if self._step_done("run_scan"):
            return
        result = _scan_main.run(
            self.state.target,
            self.state.objective,
            self.state.scope,
        )
        # CVE/exploit-Flags + Pfade aus workflow_last.json lesen.
        # workflow_last.json wird von _save_outputs() zuverlässig geschrieben und
        # enthält die deserialisierten Pydantic-Felder. result.tasks_output.pydantic
        # kann zu diesem Zeitpunkt None sein (CrewAI gibt es nicht immer zurück).
        try:
            last = os.path.join(LOG_DIR, "workflow_last.json")
            with open(last) as f:
                summary = json.load(f)
            self.state.scan_report_path = summary.get("report", "")
            self.state.scan_json_path   = last
            tasks = summary.get("tasks", {})
            cves = tasks.get("findings", {}).get("cve_references", [])
            if cves:
                self.state.has_cve_findings = True
            attack_surface = tasks.get("red", {}).get("attack_surface_count", 0)
            if attack_surface and attack_surface > 0:
                self.state.has_exploitable = True
        except Exception:
            pass
        self._mark_step("run_scan")

    @router(run_scan)
    def route_results(self) -> str:
        if self.state.has_exploitable:
            return "full_analysis"     # interpret + threat_intel + compliance + risk
        if self.state.has_cve_findings:
            return "cve_analysis"      # interpret + compliance + risk
        return "clean"                 # direkt reporting

    @listen(or_("full_analysis", "cve_analysis"))
    def run_interpret(self):
        if self._step_done("run_interpret"):
            return
        console.print()
        console.print("  [bold yellow]→ interpret-agent[/]  CVE Enrichment läuft...")
        flow = _interpret.run_interpret_flow(self.state.scan_json_path)
        self.state.nvd_results = flow.state.nvd_results
        self._mark_step("run_interpret")

    @listen(run_interpret)
    def run_threat_intel(self):
        if self._step_done("run_threat_intel"):
            return
        # Aktiv nur bei full_analysis (has_exploitable); no-op bei cve_analysis.
        if not self.state.has_exploitable:
            self._mark_step("run_threat_intel")
            return
        console.print()
        console.print("  [bold red]→ threatintel-agent[/]  Threat Intelligence läuft...")
        flow = _threatintel.run_threatintel_flow(self.state.scan_json_path)
        self.state.threat_intel_output = flow.state.threat_summary
        self._mark_step("run_threat_intel")

    @listen(run_threat_intel)
    def run_compliance(self):
        if self._step_done("run_compliance"):
            return
        console.print()
        console.print("  [bold magenta]→ compliance-agent[/]  OWASP Mapping läuft...")
        flow = _compliance.run_compliance_flow(self.state.scan_json_path)
        self.state.compliance_output = flow.state.mapping_result
        self._mark_step("run_compliance")

    @listen(run_compliance)
    def run_risk_scorer(self):
        if self._step_done("run_risk_scorer"):
            return
        console.print()
        console.print("  [bold blue]→ risk-scorer[/]  Risk Score wird berechnet...")
        flow = _risk.run_risk_flow(
            scan_json_path      = self.state.scan_json_path,
            nvd_results         = self.state.nvd_results,
            threat_intel_output = self.state.threat_intel_output,
            compliance_output   = self.state.compliance_output,
            has_exploitable     = self.state.has_exploitable,
        )
        self.state.risk_score_output = (
            f"Score: {flow.state.risk_score} / 10 — {flow.state.risk_level}"
        )
        self._mark_step("run_risk_scorer")

    @listen("clean")
    def skip_teams(self):
        """CLEAN-Route — keine CVEs, Teams 4+5+6 werden übersprungen."""
        console.print()
        console.print("  [bold green]→ Route: CLEAN[/]  Keine CVEs — Teams 4+5+6 übersprungen.")

    @listen(or_(run_risk_scorer, skip_teams))
    def run_reporting(self):
        if self._step_done("run_reporting"):
            return
        console.print()
        console.print("  [bold cyan]→ reporting[/]  Final Report wird erstellt...")
        flow = _reporting.run_reporting_flow(
            scan_target      = self.state.target,
            scan_report_path = self.state.scan_report_path,
            nvd_results      = self.state.nvd_results,
        )
        self.state.final_report_path = flow.state.final_report_path
        self._mark_step("run_reporting")


# ─── Entry points ─────────────────────────────────────────────────────────────

def run_flow(target: str, objective: str = "", scope: str = "full") -> ReconSuiteFlow:
    flow = ReconSuiteFlow()
    flow.state.target    = target
    flow.state.objective = objective
    flow.state.scope     = scope
    console.print(f"\n  [dim]Flow ID:[/]  [cyan]{flow.state.id}[/]  [dim](--resume to resume)[/]")
    flow.kickoff()
    console.print(f"\n  [dim]Flow ID:[/]  [cyan]{flow.state.id}[/]")
    return flow


def resume_flow(state_id: str) -> ReconSuiteFlow:
    """Resumes a previously persisted flow run from its last saved state."""
    flow = ReconSuiteFlow()
    console.print(f"\n  [dim]Resuming flow:[/]  [cyan]{state_id}[/]")
    flow.kickoff(restore_from_state_id=state_id)
    return flow


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--resume":
        if len(args) < 2:
            console.print("[red]✗[/]  --resume requires a flow ID")
            sys.exit(1)
        resume_flow(args[1])
    elif len(args) >= 1:
        _target    = args[0]
        _objective = args[1] if len(args) >= 2 else ""
        _scope     = args[2] if len(args) >= 3 else "full"
        run_flow(_target, _objective, _scope)
    else:
        import sys as _sys
        # Flush stdin before prompting — stale input from a previous Ctrl+C can
        # pre-fill the first Prompt.ask() and corrupt target/objective values.
        try:
            import termios
            termios.tcflush(_sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass
        console.print()
        _target    = Prompt.ask("[bold]Target[/] [dim](domain or IP)[/]").strip()
        _objective = Prompt.ask(
            "[bold]Objective[/] [dim](Enter für full scan)[/]", default=""
        ).strip()
        console.print(
            "  [dim]Scopes:[/]  "
            "[cyan]osint[/] · [cyan]ssl[/] · [cyan]quick[/] · "
            "[cyan]web[/] · [cyan]network[/] · [cyan]full[/]"
        )
        _scope = Prompt.ask("[bold]Scope[/]", default="full").strip()
        run_flow(_target, _objective, _scope)
