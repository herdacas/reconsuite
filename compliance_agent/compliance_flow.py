"""
compliance_agent/compliance_flow.py — Team 5: Compliance Mapper

Mapped Scan-Findings auf OWASP Top 10 (2025) via Knowledge Source.
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
    # Pentest-Scope (2026-06-25): PoC-Schranke. Remediation-Empfehlungen werden NUR
    # ausgegeben wenn die Ausnutzbarkeit nachgewiesen ist (red-Phase exploitable_findings).
    # Deterministisch aus dem crew-JSON gelesen — kein LLM-Ermessen.
    has_poc:          bool      = False
    exploitable_items: list[str] = Field(default_factory=list)
    poc_hits:         list[dict] = Field(default_factory=list)  # [{cve, severity, url}]


# ─── PoC-Extraktion (deterministisch) ────────────────────────────────────────

def _extract_nuclei_poc(scan_json_path: str) -> list[dict]:
    """Extrahiert framework-verifizierte PoC-Treffer aus dem nuclei-Trace.

    Strikte PoC-Definition (Pentest-Scope): nur was nuclei AKTIV gegen das Target
    bestätigt hat. nuclei-Trefferzeilen haben die Form
        [CVE-2020-2551] [http] [critical] http://host:7001/console/...
    → das ist ein verifizierter Treffer mit Endpunkt (Basis für Exploit-Entwicklung).
    [WRN]/[INF]-Zeilen sind KEINE Treffer und werden ignoriert.

    Liest den trace_<target>_<ts>.json passend zum scan_json (crew_<target>_<ts>.json).
    """
    import glob
    import json as _json
    import os as _os
    import re as _re

    if not scan_json_path:
        return []
    # crew_<target>_<ts>.json → trace_<target>_<ts>.json
    base = _os.path.basename(scan_json_path).replace("crew_", "trace_")
    trace_path = _os.path.join(_os.path.dirname(scan_json_path), base)
    if not _os.path.exists(trace_path):
        # Fallback: neuester Trace im selben Verzeichnis
        cands = glob.glob(_os.path.join(_os.path.dirname(scan_json_path) or ".", "trace_*.json"))
        if not cands:
            return []
        trace_path = max(cands, key=_os.path.getmtime)

    try:
        trace = _json.load(open(trace_path))
    except Exception:
        return []

    # Zeile: [CVE-ID] [proto] [severity] URL   (severity nur high/critical zählt als PoC)
    pat = _re.compile(
        r"\[(CVE-\d{4}-\d{4,7})\]\s*\[[^\]]+\]\s*\[(critical|high)\]\s*(\S+)", _re.IGNORECASE
    )
    hits: dict[str, dict] = {}
    for pd in trace.get("phases", {}).values():
        for c in pd.get("tool_calls", []):
            if "nuclei" not in (c.get("tool_name", "") or ""):
                continue
            for m in pat.finditer(c.get("raw_output", "") or ""):
                cve = m.group(1).upper()
                hits.setdefault(cve, {"cve": cve, "severity": m.group(2).lower(),
                                      "url": m.group(3)})
    return list(hits.values())


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

        # PoC-Schranke STRIKT + deterministisch: nur was nuclei AKTIV gegen DIESES
        # Target verifiziert hat zählt als nachgewiesen ausnutzbar (nicht die LLM-
        # Einschätzung 'PoC existiert irgendwo'). nuclei-Trefferzeilen der Form
        # "[CVE-…] [http] [critical|high] <URL>" sind framework-verifizierte Treffer
        # mit konkretem Endpunkt — genau die Basis für Exploit-Entwicklung.
        # Die [WRN]/[INF]-Zeilen sind KEINE Treffer.
        import re as _re
        self.state.poc_hits = _extract_nuclei_poc(self.state.scan_json_path)
        self.state.has_poc = len(self.state.poc_hits) > 0
        self.state.exploitable_items = [h["cve"] for h in self.state.poc_hits]

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
                "Analysiere Scan-Findings und mappe sie auf OWASP Top 10 (2025). "
                "Nutze deine Knowledge Source für das exakte Mapping. "
                "Sei präzise — nur Findings die klar einem OWASP-Kategorie zugeordnet werden können."
            ),
            backstory=(
                "Du bist spezialisiert auf Compliance-Mapping von Security-Assessment-Findings. "
                "Du kennst OWASP Top 10 (2025) auswendig und weißt welche technischen Findings "
                "welchen Kategorien entsprechen. Du arbeitest faktenbasiert — "
                "kein Spekulieren, nur direkte Mapping auf Basis der vorliegenden Findings."
            ),
            llm=llm,
            knowledge_sources=[owasp_knowledge],
            allow_delegation=False,
            memory=False,
            verbose=False,
            max_iter=3,
            # Sollbruchstelle gegen hängende Remote-LLM-Calls (Audit-Empfehlung 3,
            # 2026-09-15, roadmap.md). 1200s: ~3.6x der höchsten real beobachteten
            # Laufzeit (max 335.1s, logs/llm_debug_*.jsonl).
            max_execution_time=1200,
            respect_context_window=True,
        )

        # Pentest-Scope (2026-06-25): Terminologie auf Ausnutzung/Angriffsvektor statt
        # Defender-Empfehlung. Remediation NUR bei nachgewiesener Ausnutzbarkeit (PoC).
        if self.state.has_poc:
            _poc_lines = "\n".join(
                f"  - {h['cve']} ({h['severity']}) → verifiziert an {h['url']}"
                for h in self.state.poc_hits[:20]
            )
            _poc_block = (
                "AUSNUTZBARKEIT FRAMEWORK-VERIFIZIERT (nuclei-Treffer gegen dieses Target):\n"
                f"{_poc_lines}\n\n"
                "Für diese verifizierten Findings:\n"
                "4. Angriffsvektor & Exploit-Ansatz: Bereite die Tool-Daten so auf dass sie zur "
                "EXPLOIT-ENTWICKLUNG weiterverwendet werden können — konkreter Endpunkt/URL, "
                "betroffene Komponente, Exploit-Typ (RCE/Deserialization/Path-Traversal/…), "
                "benötigte Vorbedingungen. KEINE allgemeine Theorie, sondern verwertbare Angriffspunkte.\n"
                "5. Remediation: NUR für die oben framework-verifizierten Findings EIN knapper Satz. "
                "Für alle NICHT-verifizierten Findings KEINE Remediation.\n\n"
            )
        else:
            _poc_block = (
                "KEINE Ausnutzbarkeit gegen dieses Target verifiziert (keine nuclei-Treffer).\n\n"
                "4. Angriffsfläche & Ansatzpunkte: Bereite die vorhandenen Tool-Daten so auf dass "
                "ein Pentester sie für die WEITERE EXPLOIT-ENTWICKLUNG nutzen kann — exponierte "
                "Dienste/Versionen, interessante Endpunkte, Konfigurations-Hinweise, mögliche "
                "Angriffsvektoren. Bleibe bei dem was die Tools liefern (keine Spekulation).\n"
                "WICHTIG (Pentest-Scope): Ohne verifizierten PoC werden KEINE Security-Verbesserungs-, "
                "Remediation- oder Härtungsempfehlungen gegeben. KEINE Begriffe wie 'implementieren', "
                "'aktualisieren', 'absichern', 'härten', 'sollte konfiguriert werden'. NUR Angriffsfläche "
                "und Ausnutzungs-Ansätze beschreiben.\n"
                "WORTWAHL — WICHTIG: Es gibt KEINEN gegen dieses Target nachgewiesenen Exploit. "
                "Eine CVE die nur in NVD existiert oder 'in-the-wild' bekannt ist, ist NICHT "
                "'nachgewiesen ausnutzbar'. Verwende daher AUSSCHLIESSLICH: 'POTENZIELL ausnutzbar', "
                "'publiziert/bekannt-ausgenutzt (Versions-Match, aber kein PoC gegen dieses Target)', "
                "'Ansatzpunkt für weitere Tests'. NIE 'nachgewiesen ausnutzbar' / 'bestätigt ausnutzbar' / "
                "'confirmed exploitable'. SEVERITY ohne PoC höchstens 'High', NICHT 'Critical' — "
                "Critical setzt einen verifizierten Exploit-Pfad voraus.\n\n"
            )

        mapping_task = Task(
            description=(
                f"Du bist Teil eines PENETRATIONSTESTS (nicht eines defensiven Audits). "
                f"Mappe die folgenden Findings von {self.state.scan_target} auf OWASP Top 10 (2025) "
                f"aus ANGREIFER-Perspektive.\n\n"
                f"FINDINGS:\n{self.state.findings_text[:6000]}\n\n"
                f"{_poc_block}"
                "Erstelle für jede relevante OWASP-Kategorie die betroffen ist:\n"
                "1. OWASP-ID und Name (z.B. A03:2025 – Software Supply Chain Failures)\n"
                "2. Konkrete Findings die dieser Kategorie zugeordnet werden\n"
                "3. Severity: Critical / High / Medium / Low\n"
                "(Punkt 4/5 siehe oben — abhängig vom PoC-Status)\n\n"
                "Nutze deine Knowledge Source für das Mapping. "
                "Nur Kategorien die tatsächlich betroffen sind — keine Spekulation."
            ),
            expected_output=(
                "Strukturierter Pentest-OWASP-Report im Markdown-Format:\n"
                "## OWASP Top 10 Mapping (Angreifer-Perspektive)\n"
                "### A0X:2025 – Name\n"
                "- **Findings:** ...\n"
                "- **Severity:** ...\n"
                "- **Angriffsvektor:** ... (wie ausnutzbar)\n"
                "- **Remediation:** NUR bei nachgewiesenem PoC, sonst weglassen\n"
                "Abschließend: ## Summary mit Bewertung der Angriffsfläche."
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
            "**Framework:** OWASP Top 10 — 2025\n",
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
