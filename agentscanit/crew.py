"""
crew.py – AgentScanITCrew: Flow-ready Crew-Klasse

Standalone (via main.py):
    python3 main.py example.com "objective" full

Als Flow-Crew:
    from crew import AgentScanITCrew

    class SecurityFlow(Flow):
        @start()
        def recon(self):
            return AgentScanITCrew(
                target=self.state.target,
                objective=self.state.objective,
                scope="full",
            ).crew().kickoff(inputs=...)
"""

import json
import re
import requests
from pathlib import Path

from crewai import Crew, Process
from crewai.memory import Memory
from crewai.memory.storage.lancedb_storage import LanceDBStorage
from typing import Any
from rich.console import Console

from config import OLLAMA_API_KEY, ACTIVE_ANALYSIS, ACTIVE_BASE_URL, EMBED_MODEL, EMBED_BASE_URL
from agents import research_agent, blue_agent, red_agent, coding_agent, reporter_agent
from tasks  import (
    research_task, blue_task, findings_task,
    red_scan_task, red_task, coding_task, report_task,
)

console = Console()


# ─── Memory ───────────────────────────────────────────────────────────────────

MEMORY_DIR = Path(__file__).parent / "memory"
MEMORY_DIR.mkdir(exist_ok=True)

# Remote: plain model name — LiteLLM picks up OPENAI_BASE_URL from env.
# Local:  ollama/ prefix — LiteLLM routes to localhost:11434 by default.
_memory_llm = ACTIVE_ANALYSIS if OLLAMA_API_KEY else f"ollama/{ACTIVE_ANALYSIS}"


class _ShallowMemory(Memory):
    """Memory subclass that forces depth='shallow' on every recall.

    Why: CrewAI's deep recall uses RecallFlow.filter_and_chunk() which calls
    list_scopes('/') to pick candidate scopes. Our LanceDB has 99 % of rows at
    scope '/' (LLM save-analysis fails → default scope used). list_scopes only
    finds the rare '/security' sub-scope, so the WHERE filter excludes almost
    all rows. Shallow recall skips list_scopes entirely and does a direct
    vector search over all rows — which is exactly what we need.
    """

    def recall(self, query: str, **kwargs: Any) -> list:
        kwargs["depth"] = "shallow"
        return super().recall(query, **kwargs)


_crew_memory = _ShallowMemory(
    llm=_memory_llm,
    storage=LanceDBStorage(path=str(MEMORY_DIR / "lancedb")),
    embedder={
        "provider": "ollama",
        "config": {
            "model": EMBED_MODEL,
            "url": f"{EMBED_BASE_URL}/api/embeddings",
        },
    },
)


# ─── Task / Agent Registry ────────────────────────────────────────────────────

_TASK_ORDER = ["research", "blue", "findings", "red_scan", "red", "coding", "report"]

_ALL_TASKS = {
    "research": research_task,
    "blue":     blue_task,
    "findings": findings_task,
    "red_scan": red_scan_task,
    "red":      red_task,
    "coding":   coding_task,
    "report":   report_task,
}

TASK_LABEL = {id(t): name for name, t in _ALL_TASKS.items()}

_TASK_AGENT = {
    "research": research_agent,
    "blue":     blue_agent,
    "findings": research_agent,
    "red_scan": blue_agent,
    "red":      red_agent,
    "coding":   coding_agent,
    "report":   reporter_agent,
}

VALID_SCOPES = {"osint", "ssl", "quick", "web", "network", "full"}

_SCOPE_CEILING: dict[str, set] = {
    "osint":   {"research", "report"},
    "ssl":     {"research", "blue", "report"},
    "quick":   {"research", "blue", "findings", "report"},
    "web":     {"research", "blue", "findings", "red", "report"},
    "network": {"research", "blue", "findings", "red", "report"},
    "full":    {"research", "blue", "findings", "red_scan", "red", "coding", "report"},
}

PHASE_LABEL = {
    "research": "Research & OSINT",
    "blue":     "Active Scanning",
    "findings": "CVE Analysis",
    "red_scan": "Targeted Follow-up Scan",
    "red":      "Exploitability Analysis",
    "coding":   "Script Generation",
    "report":   "Report",
}


# ─── Planner ──────────────────────────────────────────────────────────────────

_PLANNER_PROMPT = """\
You are a pentest orchestrator. Your ONLY job: decide which pipeline phases are needed.

Target:    {target}
Objective: {objective}
Scope:     {scope}

Available phases (in this fixed order):
{allowed_list}

Phase descriptions:
- research  : passive recon – DNS, WHOIS, OSINT, subdomain enumeration (always needed)
- blue      : active scanning – nmap, nikto, httpx, sslscan, testssl, nuclei
- findings  : CVE research for discovered services (only meaningful after blue)
- red_scan  : targeted follow-up scan – nuclei/nikto re-run with CVE-specific parameters from findings (scope=full only)
- red       : exploit analysis from attacker perspective (only meaningful after findings)
- coding    : generate a Python automation script (only if explicitly requested)
- report    : write the final report (always needed)

Selection rules:
- "research" and "report" are ALWAYS required
- Include "blue" whenever the objective mentions: vulnerabilities, CVEs, scanning, ports, services,
  web stack, security assessment, SSL, TLS, headers, technology fingerprinting, or any active check
- Include "blue" for scopes web/network/full — passive OSINT alone is insufficient for these scopes
- "findings" whenever "blue" is selected — CVE lookup is always useful after scanning
- "red_scan" only if "findings" is selected AND scope is "full"
- "red" whenever "findings" is selected
- "coding" only if the objective explicitly asks for a script or automation
- Only omit "blue" if the scope is "osint" or "ssl", or the objective is purely passive (whois/DNS only)

Examples:
- scope=osint, objective "passive recon" → {{"tasks": ["research", "report"]}}
- scope=web,   objective "web vulnerabilities" → {{"tasks": ["research", "blue", "findings", "red", "report"]}}
- scope=full,  objective "full assessment"     → {{"tasks": ["research", "blue", "findings", "red_scan", "red", "report"]}}
- scope=quick, objective "whois and IP"        → {{"tasks": ["research", "report"]}}

Reply with ONLY a JSON object, no explanation, no markdown."""


_PLANNER_SIMPLE_PROMPT = """\
Reply with ONLY a JSON object. No explanation, no markdown.
Choose from: {allowed}
Rules: always include "research" and "report".
Include "blue"+"findings"+"red" when the objective involves scanning or vulnerabilities.
Objective: {objective}
Example for vulnerability scan: {{"tasks": ["research", "blue", "findings", "red", "report"]}}"""


def _extract_planner_json(content: str) -> dict | None:
    """Try multiple strategies to extract JSON from an LLM planner response."""
    try:
        return json.loads(content.strip())
    except Exception:
        pass
    stripped = re.sub(r'```(?:json)?\s*', '', content).strip().rstrip('`').strip()
    try:
        return json.loads(stripped)
    except Exception:
        pass
    match = re.search(r'\{.*\}', content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except Exception:
            pass
    return None


def _call_planner(target: str, objective: str, scope: str) -> set[str]:
    ceiling      = _SCOPE_CEILING[scope]
    allowed      = [t for t in _TASK_ORDER if t in ceiling]
    allowed_list = "\n".join(f"- {t}" for t in allowed)

    headers = {"Content-Type": "application/json"}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"

    def _post(messages: list) -> str:
        payload = {
            "model":   ACTIVE_ANALYSIS,
            "messages": messages,
            "stream":  False,
            "options": {"temperature": 0.1, "num_predict": 300},
        }
        resp = requests.post(
            f"{ACTIVE_BASE_URL}/api/chat",
            headers=headers,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()

    content = _post([{"role": "user", "content": _PLANNER_PROMPT.format(
        target=target, objective=objective, scope=scope, allowed_list=allowed_list,
    )}])
    data = _extract_planner_json(content)

    if data is None:
        simple  = _PLANNER_SIMPLE_PROMPT.format(
            allowed=", ".join(allowed),
            objective=objective[:100],
        )
        content = _post([{"role": "user", "content": simple}])
        data    = _extract_planner_json(content)

    if data is None:
        raise ValueError(f"No JSON in planner response: {content[:120]}")

    chosen = set(data.get("tasks", []))
    if not chosen:
        raise ValueError(f"Empty task list: {data}")
    return chosen


def plan_tasks(target: str, objective: str, scope: str) -> tuple[list, list]:
    ceiling = _SCOPE_CEILING[scope]

    console.print("  [dim]Analysing objective...[/]", end="")
    try:
        chosen = _call_planner(target, objective, scope)

        chosen = chosen & ceiling
        chosen |= {"research", "report"}
        if "findings" in chosen and "blue" not in chosen:
            chosen.discard("findings")
        if "red_scan" in chosen and "findings" not in chosen:
            chosen.discard("red_scan")
        if "red" in chosen and "findings" not in chosen:
            chosen.discard("red")
        if "coding" in chosen and "blue" not in chosen:
            chosen.discard("coding")

        labels = [t for t in _TASK_ORDER if t in chosen]
        console.print(f"  [green]done[/]")

    except Exception as exc:
        labels = [t for t in _TASK_ORDER if t in ceiling]
        console.print(f"  [yellow]fallback[/] [dim]({exc.__class__.__name__})[/]")

    active_tasks = [_ALL_TASKS[t] for t in labels]
    seen         = set()
    active_agents = []
    for t in labels:
        agent = _TASK_AGENT[t]
        if id(agent) not in seen:
            seen.add(id(agent))
            active_agents.append(agent)

    return active_tasks, active_agents


# ─── Crew-Klasse (Flow-ready) ─────────────────────────────────────────────────

class AgentScanITCrew:
    """Vulnerability scanner crew — standalone oder als Teil eines CrewAI Flows.

    Standalone:
        result = AgentScanITCrew(target, objective, scope).crew().kickoff(inputs=...)

    In einem Flow:
        @start()
        def recon(self):
            return AgentScanITCrew(self.state.target, ...).crew().kickoff(inputs=...)
    """

    def __init__(self, target: str, objective: str = "", scope: str = "full"):
        self.scope = scope.lower().strip()
        if self.scope not in VALID_SCOPES:
            self.scope = "full"
        self.target    = target
        self.objective = objective or f"Full vulnerability assessment of {target}"
        self._active_tasks:  list = []
        self._active_agents: list = []

    def crew(self, task_callback=None) -> Crew:
        """Ruft den Planner auf, assembliert die Crew und gibt sie zurück.

        task_callback: optionale Funktion die nach jeder Phase aufgerufen wird.
        Nach dem Aufruf ist self.pipeline verfügbar.
        """
        self._active_tasks, self._active_agents = plan_tasks(
            self.target, self.objective, self.scope
        )
        return Crew(
            agents=self._active_agents,
            tasks=self._active_tasks,
            process=Process.sequential,
            memory=_crew_memory,
            cache=True,
            verbose=False,
            task_callback=task_callback,
        )

    @property
    def pipeline(self) -> list[str]:
        """Task-Namen der geplanten Pipeline (nach crew()-Aufruf verfügbar)."""
        return [TASK_LABEL.get(id(t), "?") for t in self._active_tasks]

    @property
    def inputs(self) -> dict:
        """Standard-Inputs für crew().kickoff()."""
        return {
            "target":    self.target,
            "objective": self.objective,
            "scope":     self.scope,
        }
