"""
recon-suite/flow.py — Master-Flow

Orchestriert die drei Teams sequentiell:
    1. agentscanit     → Active Recon & Enumeration
    2. interpret-agent → CVE Enrichment (NVD API v2)
    3. reporting       → Final Report (Merge)

Routing nach dem Scan:
    exploitable  → interpret + reporting
    cve_found    → interpret + reporting
    clean        → nur reporting (kein NVD-Lookup nötig)

Usage:
    python3 flow.py example.com "full assessment" full
    from flow import run_flow
"""

import sys
import os
import json

# ── Teams registrieren ─────────────────────────────────────────────────────────
_SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SUITE_DIR)

import agentscanit.main as _scan_main       # lädt CrewAI-Patches als Seiteneffekt
from agentscanit import AgentScanITCrew
import interpret_agent as _interpret        # Verzeichnis: interpret_agent/
import reporting as _reporting             # Verzeichnis: reporting/

from pydantic import BaseModel, Field
from crewai.flow.flow import Flow, start, listen, router
from rich.console import Console
from rich.prompt import Prompt

LOG_DIR = os.path.join(_SUITE_DIR, "logs")
console = Console()


# ─── State ────────────────────────────────────────────────────────────────────

class ScanState(BaseModel):
    target:            str        = ""
    objective:         str        = ""
    scope:             str        = "full"
    pipeline:          list[str]  = Field(default_factory=list)
    has_cve_findings:  bool       = False
    has_exploitable:   bool       = False
    scan_report_path:  str        = ""
    scan_json_path:    str        = ""
    nvd_results:       list[dict] = Field(default_factory=list)
    final_report_path: str        = ""


# ─── Flow ─────────────────────────────────────────────────────────────────────

class ReconSuiteFlow(Flow[ScanState]):
    """Master-Flow: agentscanit → interpret-agent → reporting."""

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
        result = _scan_main.run(
            self.state.target,
            self.state.objective,
            self.state.scope,
        )
        # CVE/exploit-Flags für Routing
        if hasattr(result, "tasks_output") and result.tasks_output:
            for task_out in result.tasks_output:
                if not (hasattr(task_out, "pydantic") and task_out.pydantic):
                    continue
                pd = task_out.pydantic
                if hasattr(pd, "cve_references") and pd.cve_references:
                    self.state.has_cve_findings = True
                if hasattr(pd, "exploitable_findings") and pd.exploitable_findings:
                    self.state.has_exploitable = True

        # Pfade aus workflow_last.json
        try:
            last = os.path.join(LOG_DIR, "workflow_last.json")
            with open(last) as f:
                summary = json.load(f)
            self.state.scan_report_path = summary.get("report", "")
            self.state.scan_json_path   = last
        except Exception:
            pass

    @router(run_scan)
    def route_results(self) -> str:
        if self.state.has_exploitable or self.state.has_cve_findings:
            return "needs_interpret"
        return "clean"

    @listen("needs_interpret")
    def run_interpret(self):
        console.print()
        console.print("  [bold yellow]→ interpret-agent[/]  CVE Enrichment läuft...")
        flow = _interpret.run_interpret_flow(self.state.scan_json_path)
        self.state.nvd_results = flow.state.nvd_results

    @listen("clean")
    def skip_interpret(self):
        console.print()
        console.print("  [bold green]→ Route: CLEAN[/]  Keine CVEs — kein NVD-Lookup nötig.")

    @listen(run_interpret)
    @listen(skip_interpret)
    def run_reporting(self):
        console.print()
        console.print("  [bold cyan]→ reporting[/]  Final Report wird erstellt...")
        flow = _reporting.run_reporting_flow(
            scan_target      = self.state.target,
            scan_report_path = self.state.scan_report_path,
            nvd_results      = self.state.nvd_results,
        )
        self.state.final_report_path = flow.state.final_report_path


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_flow(target: str, objective: str = "", scope: str = "full") -> ReconSuiteFlow:
    flow = ReconSuiteFlow()
    flow.state.target    = target
    flow.state.objective = objective
    flow.state.scope     = scope
    flow.kickoff()
    return flow


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 1:
        _target    = args[0]
        _objective = args[1] if len(args) >= 2 else ""
        _scope     = args[2] if len(args) >= 3 else "full"
    else:
        console.print()
        _target    = Prompt.ask("[bold]Target[/] [dim](domain or IP)[/]")
        _objective = Prompt.ask(
            "[bold]Objective[/] [dim](Enter für full scan)[/]", default=""
        )
        console.print(
            "  [dim]Scopes:[/]  "
            "[cyan]osint[/] · [cyan]ssl[/] · [cyan]quick[/] · "
            "[cyan]web[/] · [cyan]network[/] · [cyan]full[/]"
        )
        _scope = Prompt.ask("[bold]Scope[/]", default="full")

    run_flow(_target, _objective, _scope)
