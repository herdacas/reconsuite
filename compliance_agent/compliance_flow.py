"""
compliance_agent/compliance_flow.py — Team 5: Compliance Mapper

Mapped Scan-Findings auf OWASP Top 10 (2021) via Knowledge Source.
Nutzt einen CrewAI Agent mit owasp_knowledge — kein Internet-Lookup nötig,
alles aus der lokal eingebetteten Knowledge Source.

Eingabe:  workflow_last.json (Findings aus Team 1)
Ausgabe:  logs/compliance_<target>_<ts>.md
"""

import json
import os
import re
import sys
from datetime import datetime

from pydantic import BaseModel, Field
from crewai import Agent, Crew, Task, LLM
from crewai.flow.flow import Flow, start, listen
from rich.console import Console
from rich.panel import Panel

_TEAM_DIR  = os.path.dirname(os.path.abspath(__file__))
_SUITE_DIR = os.path.dirname(_TEAM_DIR)

# agentscanit muss im Pfad sein für config + knowledge
sys.path.insert(0, os.path.join(_SUITE_DIR, "agentscanit"))

from config import (
    ACTIVE_ANALYSIS, ACTIVE_BASE_URL, OLLAMA_API_KEY,
    TEMP_ANALYSIS, EMBED_MODEL, EMBED_BASE_URL,
)
from knowledge.owasp import owasp_knowledge

LOG_DIR = os.path.join(_SUITE_DIR, "logs")

console = Console()


# ─── State ────────────────────────────────────────────────────────────────────

class ComplianceState(BaseModel):
    scan_json_path: str       = ""
    scan_target:    str       = ""
    findings_text:  str       = ""
    mapping_result: str       = ""
    report_path:    str       = ""


# ─── LLM ─────────────────────────────────────────────────────────────────────

def _make_llm() -> LLM:
    kwargs = dict(
        model=f"ollama/{ACTIVE_ANALYSIS}",
        base_url=ACTIVE_BASE_URL,
        temperature=TEMP_ANALYSIS,
        extra_body={"think": False, "keep_alive": "30m", "num_ctx": 8192},
    )
    if OLLAMA_API_KEY:
        kwargs["api_key"] = OLLAMA_API_KEY
    return LLM(**kwargs)


# ─── Flow ─────────────────────────────────────────────────────────────────────

class ComplianceFlow(Flow[ComplianceState]):
    """OWASP Top 10 Compliance Mapping via Knowledge Source."""

    @start()
    def load_findings(self):
        path = self.state.scan_json_path or os.path.join(LOG_DIR, "workflow_last.json")

        try:
            with open(path) as f:
                summary = json.load(f)
        except Exception as e:
            console.print(f"  [red]✗[/]  ComplianceFlow: {e}")
            return

        self.state.scan_target = summary.get("target", "unknown")

        # Findings-Text aus allen Tasks aggregieren (preview-Felder)
        parts: list[str] = []
        for task_name, task_data in summary.get("tasks", {}).items():
            preview = task_data.get("preview", "")
            if preview:
                parts.append(f"[{task_name}]\n{preview}")
        self.state.findings_text = "\n\n".join(parts)

        console.print()
        console.print(Panel(
            f"[bold magenta]compliance-agent[/]  ·  OWASP Top 10 Mapping\n\n"
            f"  [dim]Target:[/]  [bold white]{self.state.scan_target}[/]\n"
            f"  [dim]Findings:[/]  {len(parts)} Task(s) geladen",
            border_style="magenta", expand=False, padding=(0, 2),
        ))

        if not self.state.findings_text:
            console.print("  [dim]Keine Findings — kein Mapping möglich.[/]")

    @listen(load_findings)
    def run_mapping(self):
        if not self.state.findings_text:
            return

        llm = _make_llm()

        compliance_agent = Agent(
            role="Security Compliance Analyst",
            goal=(
                "Analysiere Scan-Findings und mappe sie auf OWASP Top 10 (2021). "
                "Nutze deine Knowledge Source für das exakte Mapping. "
                "Sei präzise — nur Findings die klar einem OWASP-Kategorie zugeordnet werden können."
            ),
            backstory=(
                "Du bist spezialisiert auf Compliance-Mapping von Security-Assessment-Findings. "
                "Du kennst OWASP Top 10 (2021) auswendig und weißt welche technischen Findings "
                "welchen Kategorien entsprechen. Du arbeitest faktenbasiert — "
                "kein Spekulieren, nur direkte Mapping auf Basis der vorliegenden Findings."
            ),
            llm=llm,
            knowledge_sources=[owasp_knowledge],
            allow_delegation=False,
            memory=False,
            verbose=False,
            max_iter=3,
            respect_context_window=True,
        )

        mapping_task = Task(
            description=(
                f"Mappe die folgenden Security-Assessment-Findings von {self.state.scan_target} "
                f"auf OWASP Top 10 (2021).\n\n"
                f"FINDINGS:\n{self.state.findings_text[:6000]}\n\n"
                "Erstelle für jede relevante OWASP-Kategorie die betroffen ist:\n"
                "1. OWASP-ID und Name (z.B. A06:2021 – Vulnerable and Outdated Components)\n"
                "2. Konkrete Findings die dieser Kategorie zugeordnet werden\n"
                "3. Severity: Critical / High / Medium / Low\n"
                "4. Empfohlene Maßnahme (1-2 Sätze)\n\n"
                "Nutze deine Knowledge Source für das Mapping. "
                "Nur Kategorien die tatsächlich betroffen sind — keine Spekulation."
            ),
            expected_output=(
                "Strukturierter Compliance-Report im Markdown-Format:\n"
                "## OWASP Top 10 Mapping\n"
                "### A0X:2021 – Name\n"
                "- **Findings:** ...\n"
                "- **Severity:** ...\n"
                "- **Maßnahme:** ...\n"
                "Abschließend: ## Summary mit Gesamtbewertung."
            ),
            agent=compliance_agent,
        )

        crew = Crew(
            agents=[compliance_agent],
            tasks=[mapping_task],
            embedder={
                "provider": "ollama",
                "config": {
                    "url": f"{EMBED_BASE_URL}/api/embeddings",
                    "model_name": EMBED_MODEL,
                },
            },
            verbose=False,
        )

        result = crew.kickoff()
        self.state.mapping_result = result.raw if hasattr(result, "raw") else str(result)

    @listen(run_mapping)
    def write_report(self):
        if not self.state.mapping_result:
            return

        target   = self.state.scan_target
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe     = re.sub(r"[^\w.-]", "_", target)

        content = "\n".join([
            f"**Target:** {target}  ",
            f"**Date:** {ts_human}  ",
            "**Framework:** OWASP Top 10 — 2021\n",
            "---\n",
            f"# Compliance Mapping Report: {target}\n",
            self.state.mapping_result,
        ])

        path = os.path.join(LOG_DIR, f"compliance_{safe}_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        self.state.report_path = path
        console.print(f"  [green]✓[/]  OWASP mapping abgeschlossen")
        console.print(f"  [dim]Compliance → {path}[/]")


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_compliance_flow(scan_json_path: str = "") -> ComplianceFlow:
    flow = ComplianceFlow()
    flow.state.scan_json_path = scan_json_path
    flow.kickoff()
    return flow


if __name__ == "__main__":
    import sys as _sys
    run_compliance_flow(_sys.argv[1] if len(_sys.argv) > 1 else "")
