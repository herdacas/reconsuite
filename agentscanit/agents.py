"""
agents.py – CrewAI Agent-Definitionen für AgentScanIT
Jeder Agent hat eine klar abgegrenzte Rolle im Vulnerability Assessment Workflow.
"""

import warnings

from crewai import Agent, LLM
from rich.console import Console

from config import (
    ACTIVE_ANALYSIS, ACTIVE_CODE, ACTIVE_RESEARCH, ACTIVE_PLANNER,
    ACTIVE_BASE_URL, OLLAMA_API_KEY, PLANNER_BASE_URL,
    TEMP_ANALYSIS, TEMP_CODE, TEMP_RESEARCH,
)

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from crewai.experimental.agent_executor import AgentExecutor as _EXECUTOR_CLASS
from knowledge import service_normalization_knowledge
# Note: `_run` in tools/_base.py is the subprocess helper. Within tool classes, bare
# `_run(cmd)` calls that helper; `self._run` is the BaseTool interface method (CrewAI).
# The names are distinct in Python's scoping rules but look identical at a glance.
from tools import (
    # blue_agent – Active Scanning (naabu/ffuf/testssl/enum4linux entfernt Phase 9.1; wafw00f ergänzt)
    nmap_tool, nikto_tool, whatweb_tool, wafw00f_tool, sslscan_tool,
    curl_tool, ping_tool, nuclei_tool,
    httpx_tool,
    # research_agent – Passive Recon (9 tools; amass/assetfinder/sublist3r/waybackurls/gau/theHarvester entfernt Phase 9.1)
    ddg_search_tool, subfinder_tool,
    dnsrecon_tool, dig_tool, whois_tool,
    dnsx_tool, katana_tool, searchsploit_tool,
    # nvd (keyword fallback + CPE tool)
    nvd_tool, nvd_cpe_tool,
)

_console = Console()


def _step_callback(step_output) -> None:
    """Zeigt nach jeder Phase die genutzten Tools und Key-Findings.

    CrewAI 1.x: step_callback feuert bei jedem Agent-Schritt.
    - AgentAction (.tool + .tool_input, no .return_values): LLM intends to call a tool.
      → recorded in run_trace so record_execution() in _base._run() can merge intent with
        actual subprocess data (command, raw output, duration).
    - AgentFinish (.text with JSON Pydantic output): task completed.
      → parsed for Rich console summary output only; trace phase is closed in _on_task_done.
    """
    from tools.trace import run_trace
    import json
    try:
        # AgentAction: LLM decided to call a tool — store intent for trace merging
        if hasattr(step_output, "tool") and not hasattr(step_output, "return_values"):
            run_trace.record_agent_action(
                step_output.tool,
                getattr(step_output, "tool_input", None),
            )
            return

        raw = getattr(step_output, "text", "") or getattr(step_output, "output", "") or ""
        if not raw:
            return

        # JSON-Block extrahieren falls vorhanden
        data: dict = {}
        try:
            data = json.loads(raw)
        except Exception:
            # Suche erstes { ... letztes } ohne Backtracking-Regex.
            # Begrenzung auf 4000 chars verhindert CPU-Spike bei großen Outputs.
            snippet = raw[:4000]
            j_start = snippet.find("{")
            j_end   = snippet.rfind("}")
            if j_start != -1 and j_end > j_start:
                try:
                    data = json.loads(snippet[j_start:j_end + 1])
                except Exception:
                    pass

        parts: list[str] = []

        # Tools (BlueOutput)
        tools = data.get("tools_executed") or []
        if tools:
            parts.append("tools: " + ", ".join(f"[cyan]{t}[/]" for t in tools))

        # Offene Ports (BlueOutput)
        ports = data.get("open_ports") or []
        if ports:
            parts.append(f"ports: [yellow]{', '.join(str(p) for p in ports)}[/]")

        # Subdomains-Anzahl (ResearchOutput)
        subs = data.get("subdomains") or []
        if subs:
            parts.append(f"subdomains: [yellow]{len(subs)}[/]")

        # CVEs (FindingsOutput)
        cves = data.get("cve_references") or []
        if cves:
            parts.append("CVEs: " + ", ".join(f"[red]{c}[/]" for c in cves[:3]))

        # Bestätigte Angriffsfläche (RedOutput)
        vectors = data.get("confirmed_attack_surface") or []
        if vectors:
            parts.append(f"attack surface: [red]{len(vectors)}[/]")

        if parts:
            _console.print("    [dim]↳[/] " + "  [dim]|[/]  ".join(parts))

    except Exception:
        pass


# ─── LLM-Instanzen (eine pro Temperaturprofil) ────────────────────────────────

def _llm(model: str, temperature: float, max_tokens: int | None = None) -> LLM:
    # Output-Längen-Limit (BUG-24, 2026-09-11): ohne explizites max_tokens fällt
    # der Remote-Endpoint (ollama.com) auf einen knappen Default zurück, der bei
    # langen Reports (v.a. full-Scope mit vielen Findings) das JSON mitten im
    # Objekt abschneidet ("EOF while parsing an object" in ReportOutput —
    # beobachtet bei oldenburg.de full). 8000 remote (num_ctx=16384, lässt genug
    # Raum für Input-Context) / 4000 lokal (num_ctx=8192) als DEFAULT für alle
    # Agents außer dem Reporter (siehe llm_reporter unten, BUG-24-Folgefund
    # 2026-09-12: 8000 reichte bei westerstede.de full NICHT —
    # "Could not parse response content as the length limit was reached"
    # (completion_tokens=8000 exakt ausgeschöpft, total nur 11540 von 16384 —
    # reines max_tokens-Limit, kein Context-Overflow). caller kann override via
    # max_tokens=.
    if max_tokens is None:
        max_tokens = 8000 if OLLAMA_API_KEY else 4000
    kwargs = dict(
        model=f"ollama/{model}",
        base_url=ACTIVE_BASE_URL,
        temperature=temperature,
        timeout=300,
        max_tokens=max_tokens,
    )
    if OLLAMA_API_KEY:
        kwargs["api_key"] = OLLAMA_API_KEY
    # Disable chain-of-thought for thinking models (Qwen3, gpt-oss, etc.)
    # Applied unconditionally — local Ollama ignores it for non-thinking models,
    # remote thinking models need it to prevent reasoning bleed into JSON outputs.
    # Remote-Mode: 16384 tokens — guardrail retry context (task prompt + previous
    # agent response + guardrail feedback + tool definitions) can exceed 8192 tokens,
    # causing gpt-oss to return None → ValueError crash.
    # Local-Mode: keep 8192 — RAM constrained (64GB, no GPU, multiple models loaded).
    kwargs["extra_body"] = {
        "think":      False,
        "keep_alive": "30m",
        "num_ctx":    16384 if OLLAMA_API_KEY else 8192,
    }
    return LLM(**kwargs)

llm_analysis = _llm(ACTIVE_ANALYSIS, TEMP_ANALYSIS)
llm_code     = _llm(ACTIVE_CODE,     TEMP_CODE)
llm_research = _llm(ACTIVE_RESEARCH, TEMP_RESEARCH)

# Dedizierte LLM-Instanz für reporter_agent (BUG-24-Folgefund, 2026-09-12): der
# Report-Task erzeugt strukturell den längsten Single-Shot-Output der ganzen Pipeline
# (vollständiger Markdown-Report als ein JSON-Feld) — teilte sich bisher max_tokens=8000
# mit blue_agent/red_agent (beide llm_analysis), deren finale Turns viel kürzer sind
# (Tool-Calls + kompakte Struktur-Listen). Live beobachtet (westerstede.de full):
# completion_tokens=8000 exakt ausgeschöpft, total_tokens=11540 von num_ctx=16384 —
# reichlich Spielraum ungenutzt, das Limit war ausschließlich max_tokens, kein
# Context-Overflow. Höheres max_tokens NUR für den Reporter (nicht global auf
# llm_analysis) — blue/red bleiben bei 8000/4000, ihr Bedarf ist ungeprüft anders
# und soll nicht durch eine unbegründete globale Änderung mitbetroffen sein.
llm_reporter = _llm(ACTIVE_ANALYSIS, TEMP_ANALYSIS, max_tokens=12000 if OLLAMA_API_KEY else 6000)

# Planner LLM läuft IMMER lokal (localhost:11434) — auch im Remote-Mode.
# Grund: CrewAI AgentPlanner nutzt call_llm_native_tools (Ollama native FC-API),
# die remote Modelle (gpt-oss) nicht unterstützen → "Invalid response from LLM call - None or empty."
# PLANNER_BASE_URL ist hardcoded auf localhost; LOCAL_MODEL_PLANNER = qwen2.5:7b-instruct.
llm_planner = LLM(
    model=f"ollama/{ACTIVE_PLANNER}",
    base_url=PLANNER_BASE_URL,
    temperature=0.1,
    max_tokens=2000,
    extra_body={
        "keep_alive": "30m",
        "num_ctx":    4096,
        "think":      False,
    },
)


# ─── Agents ───────────────────────────────────────────────────────────────────

research_agent = Agent(
    role="OSINT and Reconnaissance Specialist",
    goal=(
        "Sammle alle öffentlich verfügbaren Informationen über das Ziel. "
        "Identifiziere Subdomains, genutzte Technologien und exponierte Dienste "
        "ohne direkten aktiven Kontakt zum Zielsystem."
    ),
    backstory=(
        "Du bist ein erfahrener OSINT-Analyst mit Fokus auf passive Reconnaissance. "
        "Du nutzt Suchmaschinen, Zertifikatstransparenz-Logs und DNS-Daten "
        "um ein vollständiges Bild der Angriffsfläche zu erstellen, "
        "bevor aktive Scanning-Tools eingesetzt werden. "
        "Du prüfst immer zuerst ob Informationen zum Ziel bereits bekannt sind."
    ),
    system_template=(
        "You are an authorized OSINT and Reconnaissance Specialist performing a "
        "sanctioned security assessment. Use the provided tools to collect "
        "publicly available information. Only report tool-confirmed facts."
    ),
    tools=[
        ddg_search_tool, whois_tool, dig_tool,
        dnsrecon_tool, subfinder_tool,
        dnsx_tool, katana_tool, searchsploit_tool,
        nvd_tool, nvd_cpe_tool,
    ],
    knowledge_sources=[service_normalization_knowledge],
    llm=llm_research,
    function_calling_llm=llm_research,
    executor_class=_EXECUTOR_CLASS,
    verbose=False,
    memory=False,
    allow_delegation=False,
    max_iter=20,
    step_callback=_step_callback,
    respect_context_window=True,
)

blue_agent = Agent(
    role="Blue Team Security Analyst",
    goal=(
        "Führe einen vollständigen Sicherheitsscan des Ziels durch. "
        "Identifiziere offene Ports, laufende Dienste, Softwareversionen "
        "und potenzielle Schwachstellen. "
        "Erstelle konkrete, priorisierte Absicherungsempfehlungen."
    ),
    backstory=(
        "Du bist ein Blue-Team-Analyst mit tiefem Verständnis für Netzwerksicherheit. "
        "Du setzt Tools wie nmap, nikto, whatweb und sslscan präzise und gezielt ein, "
        "interpretierst deren Output kritisch und priorisierst Findings "
        "nach Risiko und Ausnutzbarkeit. "
        "Du arbeitest ausschließlich auf autorisierten Zielsystemen."
    ),
    system_template=(
        "You are an authorized Blue Team Security Analyst performing a "
        "sanctioned security assessment. Use the provided tools to scan the target. "
        "Report only tool-confirmed findings."
    ),
    tools=[
        ping_tool, nmap_tool, httpx_tool, whatweb_tool, wafw00f_tool,
        curl_tool, nikto_tool, sslscan_tool,
        nuclei_tool,
    ],
    llm=llm_analysis,
    function_calling_llm=llm_analysis,
    executor_class=_EXECUTOR_CLASS,
    verbose=False,
    memory=False,
    allow_delegation=False,
    max_iter=20,   # erhöht von 10: mehrere Live-Subdomains × Tools (Fanout) brauchen Budget
    step_callback=_step_callback,
    respect_context_window=True,
)

red_agent = Agent(
    role="Attack Surface Analyst",
    goal=(
        "Bewerte die Scan-Ergebnisse aus Angreifer-Perspektive. "
        "Verifiziere CVE-Details und PoC-Verfügbarkeit via searchsploit und DuckDuckGo. "
        "Identifiziere die realistisch ausnutzbaren Schwachstellen und priorisiere "
        "Angriffsvektoren nach Wahrscheinlichkeit und potenziellem Schaden. "
        "Liefere eine strukturierte Ausnutzbarkeits-Analyse für das Security Assessment."
    ),
    backstory=(
        "Du bist spezialisiert auf Angriffsflächen-Analyse im Rahmen autorisierter "
        "Security Assessments. Auf Basis von Scan-Ergebnissen erkennst du Muster "
        "die auf ausnutzbare Fehlkonfigurationen oder veraltete Software hinweisen. "
        "Du nutzt searchsploit und DuckDuckGo um CVEs zu verifizieren, PoC-Verfügbarkeit "
        "zu prüfen und aktive Exploitation-Hinweise (in-the-wild) zu recherchieren. "
        "Du dokumentierst Angriffspfade präzise und nachvollziehbar – "
        "als Grundlage für Remediation, nicht für aktive Exploitation."
    ),
    system_template=(
        "You are an authorized Attack Surface Analyst performing a "
        "sanctioned security assessment. Use searchsploit, ddg and nvd "
        "to verify CVEs. Report only tool-confirmed findings."
    ),
    tools=[searchsploit_tool, ddg_search_tool, nvd_tool],
    knowledge_sources=[service_normalization_knowledge],
    llm=llm_analysis,
    function_calling_llm=llm_analysis,
    executor_class=_EXECUTOR_CLASS,
    verbose=False,
    memory=False,
    allow_delegation=False,
    max_iter=8,
    step_callback=_step_callback,
    respect_context_window=True,
)

# coding_agent hat absichtlich keine Tools — er generiert Code aus dem Task-Context
# (BlueOutput + RedOutput via context=). Tool-Calls wären hier kontraproduktiv.
coding_agent = Agent(
    role="Security Automation Developer",
    goal=(
        "Generiere sauberen, kommentierten Python-Code "
        "der die identifizierten Scan-Schritte automatisiert. "
        "Der Code soll direkt ausführbar und reproduzierbar sein."
    ),
    backstory=(
        "Du bist spezialisiert auf Security-Automatisierung. "
        "Du übersetzt Assessment-Findings und manuelle Tool-Aufrufe in "
        "strukturierten Python-Code mit klarer Fehlerbehandlung und Logging. "
        "Dein Code ist lesbar, wartbar und direkt einsetzbar."
    ),
    llm=llm_code,
    function_calling_llm=llm_code,
    executor_class=_EXECUTOR_CLASS,
    verbose=False,
    memory=False,
    allow_delegation=False,
    max_iter=5,
    step_callback=_step_callback,
    respect_context_window=True,
)

reporter_agent = Agent(
    role="Pentest Recon Report Writer",
    goal=(
        "Erstelle einen strukturierten internen Recon-Report für das Pentest-Team "
        "auf Basis aller vorangegangenen Recon- und Scan-Findings. "
        "Fokus: Ausnutzbarkeit und konkrete nächste Schritte – keine Betreiberempfehlungen."
    ),
    backstory=(
        "Du bist ein erfahrener Pentester der nach der initialen Recon-Phase "
        "einen präzisen internen Bericht für das Team erstellt. "
        "Du dokumentierst die Angriffsfläche faktenbasiert, priorisierst Findings "
        "nach realistischer Ausnutzbarkeit und zeigst auf welche Tools, Module "
        "und Techniken das Team als nächstes einsetzen soll. "
        "Dein Bericht ist ein internes Arbeitsdokument – kein Kundendokument."
    ),
    llm=llm_reporter,
    function_calling_llm=llm_reporter,
    executor_class=_EXECUTOR_CLASS,
    verbose=False,
    memory=False,
    allow_delegation=False,
    max_iter=3,
    step_callback=_step_callback,
    respect_context_window=True,
)
