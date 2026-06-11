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

import logging
import os
from pathlib import Path
from typing import Any

from crewai import Crew, Process
from crewai.memory import Memory
from crewai.memory.storage.lancedb_storage import LanceDBStorage
from pydantic import model_serializer

from config import OLLAMA_API_KEY, ACTIVE_ANALYSIS, ACTIVE_BASE_URL, EMBED_MODEL, EMBED_BASE_URL
from agents import (
    research_agent, blue_agent, red_agent, coding_agent, reporter_agent,
    llm_planner,
)
from tasks import make_tasks

# ─── Memory LLM-Call Suppression ─────────────────────────────────────────────
# CrewAI fires async LLM calls (analyze_for_save, analyze_for_consolidation,
# analyze_query) for every memory save/recall to enrich metadata. These calls
# fail against our Ollama setup (Pydantic schema mismatches, rate-limit spikes
# from concurrent requests). The embedding (vector storage/recall) works fine
# without this enrichment.
#
# Patch: replace the three analysis functions at the point where they are
# locally imported in their respective flow modules. Patching at import time is
# reliable because Python caches module objects — every call site that imported
# these names before the patch sees the new lambda.
#
# Kept in crew.py (not main.py) because this is a Memory concern, not a CLI
# concern. Any code path that creates a Crew with memory gets the patch.
def _apply_memory_patches() -> None:
    try:
        import crewai.memory.analyze as _cma
        import crewai.memory.encoding_flow as _cef
        import crewai.memory.recall_flow as _crf

        _cef.analyze_for_save = lambda content, existing_scopes, existing_categories, llm: _cma._SAVE_DEFAULTS
        _cef.analyze_for_consolidation = lambda new_content, existing_records, llm: (
            _cma.ConsolidationPlan(actions=[], insert_new=True)
        )
        _crf.analyze_query = lambda query, available_scopes, scope_info, llm: _cma.QueryAnalysis(
            keywords=[],
            suggested_scopes=(available_scopes or ["/"])[:5],
            complexity="simple",
            recall_queries=[query],
        )
    except Exception:
        pass  # non-fatal — if CrewAI refactors these modules, memory just uses defaults

    # Silence log noise from failed memory-analysis attempts
    logging.getLogger("crewai.memory.analyze").setLevel(logging.CRITICAL)
    logging.getLogger("crewai.memory").setLevel(logging.CRITICAL)

    # Suppress CrewAI's "[CrewAIEventsBus] Warning: Event pairing mismatch" console spam
    try:
        import crewai.events.event_context as _evc
        from rich.console import Console as _RichConsole
        _evc._console = _RichConsole(file=open(os.devnull, "w"))
    except Exception:
        pass

    # Hinweis (Phase 7, Stufe 1): Die früheren Checkpoint-bezogenen Patches
    # (JsonProvider.checkpoint pretty-print, EventRecord.model_dump-RWLock,
    # _do_checkpoint-Safe-Wrapper) wurden entfernt. Grund: Intra-Crew-Checkpointing
    # (CheckpointConfig) ist kein dokumentierter CrewAI-Resume-Mechanismus — Resume
    # läuft auf Flow-Ebene über @persist(SQLiteFlowPersistence). Die Patches existierten
    # nur, um die Race-Condition des Hintergrund-Checkpoint-Writes abzufedern; ohne
    # Checkpointing sind sie toter Code. Beweis-Trail: debugging/DIAGNOSIS.md.


_apply_memory_patches()


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

    Checkpoint-safe: JSON serialization returns False (a valid Memory | bool value)
    so that checkpoint writes succeed despite LanceDBStorage being non-serializable.
    The restored Crew has memory=False (cold memory, no storage) — task outputs are
    still fully restored; only warm-start recall is unavailable in the retried run.
    """

    @model_serializer(mode='plain', when_used='json')
    def _serialize_for_checkpoint(self) -> bool:
        # LanceDBStorage is not JSON-serializable.
        # Return False so Crew.checkpoint writes succeed; on restore the Crew field
        # `memory: Memory | bool` accepts False, giving a cold-memory retry run.
        return False

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

# Tasks are created per-run via make_tasks() — no module-level singletons.
# TASK_LABEL is built from each fresh task dict inside plan_tasks().

_TASK_AGENT = {
    "research": research_agent,
    "blue":     blue_agent,
    "findings": research_agent,
    "red_scan": blue_agent,
    "red":      red_agent,
    "coding":   coding_agent,
    "report":   reporter_agent,
}

VALID_SCOPES = {"osint", "ssl", "quick", "web", "network", "full", "hierarchical"}

_SCOPE_CEILING: dict[str, set] = {
    "osint":        {"research", "report"},
    "ssl":          {"research", "blue", "report"},
    "quick":        {"research", "blue", "findings", "report"},
    "web":          {"research", "blue", "findings", "red", "report"},
    "network":      {"research", "blue", "findings", "red", "report"},
    "full":         {"research", "blue", "findings", "red_scan", "red", "coding", "report"},
    "hierarchical": {"research", "blue", "findings", "red", "report"},
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


def _make_manager_agent() -> "Agent":
    """Koordinations-Agent für Process.hierarchical.

    Besitzt keine eigenen Tools — delegiert alle Aufgaben an Worker-Agents
    (research, blue, red, coding, reporter). allow_delegation=True ist
    für den Manager-Role in CrewAI's hierarchical Process erforderlich.
    """
    from agents import llm_analysis
    from crewai import Agent as _Agent
    return _Agent(
        role="Security Assessment Manager",
        goal=(
            "Koordiniere das Pentest-Team so dass jede Recon-Phase vollständig durchlaufen wird. "
            "Delegiere Aufgaben gezielt an die spezialisierten Agents und stelle sicher dass "
            "alle Findings zusammengeführt werden bevor der Report erstellt wird."
        ),
        backstory=(
            "Du leitest ein spezialisiertes Security-Assessment-Team. "
            "Du kennst die Stärken jedes Team-Mitglieds und sorgst dafür dass "
            "OSINT, Active Scanning, CVE-Analyse und Exploitability-Bewertung "
            "in der richtigen Reihenfolge und mit den richtigen Agents durchgeführt werden."
        ),
        llm=llm_analysis,
        allow_delegation=True,
        verbose=False,
        memory=False,
        respect_context_window=True,
    )


def plan_tasks(target: str, objective: str, scope: str) -> tuple[list, list, dict]:
    """Assemble tasks and agents for the given scope.

    _SCOPE_CEILING controls WHICH tasks are available. Crew(planning=True)
    then optimises HOW those tasks are executed via the built-in AgentPlanner.
    """
    ceiling = _SCOPE_CEILING[scope]
    labels  = [t for t in _TASK_ORDER if t in ceiling]

    # Fresh task instances per run — no shared singleton state across retries
    all_tasks    = make_tasks()
    active_tasks = [all_tasks[t] for t in labels]

    seen          = set()
    active_agents = []
    for t in labels:
        agent = _TASK_AGENT[t]
        if id(agent) not in seen:
            seen.add(id(agent))
            active_agents.append(agent)

    task_label = {id(task): name for name, task in all_tasks.items()}
    return active_tasks, active_agents, task_label


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
        self.target      = target
        self.objective   = objective or f"Full vulnerability assessment of {target}"
        self._active_tasks:  list = []
        self._active_agents: list = []
        self._task_label:    dict  = {}   # id(task) → name, built per-run in crew()

    def crew(self, task_callback=None) -> Crew:
        """Ruft den Planner auf, assembliert die Crew und gibt sie zurück.

        task_callback:   optionale Funktion die nach jeder Phase aufgerufen wird.
        Nach dem Aufruf sind self.pipeline und self.task_label verfügbar.

        Kein Intra-Crew-Checkpointing (Phase 7, Stufe 1): Resume läuft auf Flow-Ebene
        über @persist(SQLiteFlowPersistence). Der frühere CheckpointConfig war
        nicht-idiomatisch und race-behaftet (siehe debugging/DIAGNOSIS.md).
        """
        self._active_tasks, self._active_agents, self._task_label = plan_tasks(
            self.target, self.objective, self.scope
        )

        _knowledge_embedder = {
            "provider": "ollama",
            "config": {
                "url": f"{EMBED_BASE_URL}/api/embeddings",
                "model_name": EMBED_MODEL,
            },
        }

        # memory=False: LanceDB's Rust embedder callback fires from a background
        # thread without the GIL → PyO3 panic on save → corrupts thread-local
        # state → blue_agent's first LLM call hangs indefinitely.
        # Knowledge sources (service_normalization, OWASP) are unaffected —
        # they use CREWAI_STORAGE_DIR / _knowledge_embedder which is separate.
        if self.scope == "hierarchical":
            crew_kwargs: dict = dict(
                agents=self._active_agents,
                tasks=self._active_tasks,
                process=Process.hierarchical,
                manager_agent=_make_manager_agent(),
                memory=False,
                embedder=_knowledge_embedder,
                cache=True,
                verbose=False,
                task_callback=task_callback,
            )
        else:
            crew_kwargs = dict(
                agents=self._active_agents,
                tasks=self._active_tasks,
                process=Process.sequential,
                memory=False,
                embedder=_knowledge_embedder,
                cache=True,
                verbose=False,
                task_callback=task_callback,
            )

        return Crew(**crew_kwargs)

    @property
    def pipeline(self) -> list[str]:
        """Task-Namen der geplanten Pipeline (nach crew()-Aufruf verfügbar)."""
        return [self._task_label.get(id(t), "?") for t in self._active_tasks]

    @property
    def task_label(self) -> dict:
        """Per-run id(task) → name mapping (nach crew()-Aufruf verfügbar)."""
        return self._task_label

    @property
    def inputs(self) -> dict:
        """Standard-Inputs für crew().kickoff()."""
        return {
            "target":    self.target,
            "objective": self.objective,
            "scope":     self.scope,
        }
