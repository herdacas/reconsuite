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

import os

from crewai import Crew, Process

from config import EMBED_MODEL, EMBED_BASE_URL, LOG_DIR
from agents import (
    research_agent, blue_agent, red_agent, coding_agent, reporter_agent,
    llm_planner,
)
from tasks import make_tasks

# ─── CrewAI Console-Patches ──────────────────────────────────────────────────
# Hinweis (Phase 7, Stufe 3b): Die Memory-LLM-Suppression-Patches (analyze_for_save,
# analyze_for_consolidation, analyze_query) wurden entfernt. Grund: Alle Crews laufen
# mit memory=False — CrewAI nutzt das Memory-Subsystem während eines Scans gar nicht.
# Es gab keinen save()-Pfad mehr; die Patches schützten nur einen toten Recall-Pfad.
# Mitentfernt: _ShallowMemory + _crew_memory + LanceDB-Abhängigkeit (siehe phase7.md).
# Das „warm/fresh"-Banner basiert jetzt auf vorhandenen Reports in logs/ (kein Memory).
#
# Hinweis (Phase 7, Stufe 1): Die Checkpoint-bezogenen Patches (JsonProvider.checkpoint,
# EventRecord.model_dump-RWLock, _do_checkpoint-Wrapper) wurden entfernt — Intra-Crew-
# Checkpointing ist kein dokumentierter CrewAI-Resume-Mechanismus (Resume = Flow-@persist).
#
# Verbleibender Patch: nur die Event-Bus-Console-Stille (kosmetisch).
def _apply_crewai_patches() -> None:
    # Suppress CrewAI's "[CrewAIEventsBus] Warning: Event pairing mismatch" console spam
    try:
        import crewai.events.event_context as _evc
        from rich.console import Console as _RichConsole
        _evc._console = _RichConsole(file=open(os.devnull, "w"))
    except Exception:
        pass


def _install_llm_debug_logger() -> None:
    """Diagnostisches Roh-Request-Logging (nur bei RECON_LLM_DEBUG=1).

    Umhüllt OpenAICompletion._call_completions und schreibt pro Remote-LLM-Call
    eine Zeile nach logs/llm_debug_<pid>.jsonl: Agent-Rolle, Prompt-Größe
    (Anzahl messages + Gesamt-Zeichen), tool-Anzahl, Dauer, Erfolg/Fehler inkl.
    HTTP-Status. Erfasst AUCH den fehlschlagenden Call (anders als CrewAIs
    output_log_file, das nur nach Task-Abschluss schreibt) — für die Diagnose
    des full-Scope 500/empty-Abbruchs. Null Overhead/Risiko wenn die Env-Var
    nicht gesetzt ist (sofortiges return).
    """
    if os.environ.get("RECON_LLM_DEBUG") != "1":
        return
    try:
        from crewai.llms.providers.openai.completion import OpenAICompletion
    except Exception:
        return
    if getattr(OpenAICompletion, "_recon_debug_wrapped", False):
        return

    import json as _json
    import time as _time

    _orig = OpenAICompletion._call_completions
    _path = os.path.join(LOG_DIR, f"llm_debug_{os.getpid()}.jsonl")

    def _wrapped(self, messages, tools=None, available_functions=None,
                 from_task=None, from_agent=None, response_model=None):
        rec = {
            "ts":           _time.strftime("%H:%M:%S"),
            "agent":        getattr(from_agent, "role", "?"),
            "n_messages":   len(messages or []),
            "prompt_chars": sum(len(str(m.get("content") or "")) for m in (messages or [])),
            "n_tools":      len(tools or []),
        }
        _t0 = _time.time()
        try:
            out = _orig(self, messages, tools, available_functions,
                        from_task, from_agent, response_model)
            rec["status"]     = "ok"
            rec["resp_chars"] = len(str(out)) if out else 0
            rec["dur_s"]      = round(_time.time() - _t0, 1)
            return out
        except Exception as e:
            rec["status"]      = "ERROR"
            rec["dur_s"]       = round(_time.time() - _t0, 1)
            rec["error_type"]  = type(e).__name__
            rec["error"]       = str(e)[:300]
            rec["http_status"] = getattr(getattr(e, "response", None), "status_code", None)
            raise
        finally:
            try:
                with open(_path, "a", encoding="utf-8") as _f:
                    _f.write(_json.dumps(rec, ensure_ascii=False) + "\n")
            except Exception:
                pass

    OpenAICompletion._call_completions    = _wrapped
    OpenAICompletion._recon_debug_wrapped = True


_apply_crewai_patches()
_install_llm_debug_logger()




# ─── Memory ───────────────────────────────────────────────────────────────────

# Memory-Subsystem (Phase 7, Stufe 3b) entfernt: Crews laufen memory=False,
# der Scan nutzte das Memory nie. _ShallowMemory + _crew_memory + LanceDB sind weg.
# Das „warm/fresh"-Banner basiert jetzt auf vorhandenen Reports in logs/ (main.py).


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

    def crew(self, task_callback=None, log_llm: bool = False) -> Crew:
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

        import re as _re
        from datetime import datetime as _dt
        _safe = _re.sub(r"[^\w.-]", "_", self.target)
        _ts   = _dt.now().strftime("%Y%m%d_%H%M%S")
        _log_file = (
            os.path.join(LOG_DIR, f"llm_{_safe}_{_ts}.log") if log_llm else None
        )

        _knowledge_embedder = {
            "provider": "ollama",
            "config": {
                "url": f"{EMBED_BASE_URL}/api/embeddings",
                "model_name": EMBED_MODEL,
            },
        }

        # ─── AgentPlanner-Gate (BUG-18, 2026-06-18) ──────────────────────────
        # Der CrewAI AgentPlanner baut EINEN Plan-Prompt der ALLE Tasks +
        # Tool-Definitionen + Backstories enthält. Bei full (7 Tasks) ist dieser
        # Prompt ~129.000 Zeichen ≈ 32k Tokens groß (bewiesen via RECON_LLM_DEBUG,
        # 2026-06-18: Call #0 "Task Execution Planner", prompt_chars=129302,
        # dur=237s). Der Planner läuft lokal (qwen2.5:7b, num_ctx=4096) → der
        # 32k-Prompt überläuft das 4096-Fenster um das ~8-fache → der lokale
        # Server generiert minutenlang und kippt intermittierend in leere/
        # fehlerhafte Antworten ("Invalid response from LLM call - None or empty"),
        # was den GANZEN full-Scan abbrechen ließ. web/network (5 Tasks) bleiben
        # unter der Schwelle und liefen immer durch.
        #
        # Fix: Planner nur bei ≤5 Tasks aktiv. _SCOPE_CEILING legt die Pipeline
        # ohnehin deterministisch fest — der Planner optimiert nur die AUSFÜHRUNG,
        # nicht WELCHE Tasks laufen; bei full ist der Verlust also gering.
        #
        # TODO (echte Lösung, siehe roadmap "Offen"): Planner-Prompt für große
        # Scopes verkleinern (Task-Beschreibungen kürzen / Tools aus dem Plan-
        # Prompt nehmen) ODER Planner-num_ctx an die Prompt-Größe koppeln ODER
        # ein lokales Planner-Modell mit größerem nativem Kontext. Dann kann das
        # Gate wieder fallen.
        _use_planning = len(self._active_tasks) <= 5

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
                planning=_use_planning,
                planning_llm=llm_planner,
                task_callback=task_callback,
                output_log_file=_log_file,
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
                planning=_use_planning,
                planning_llm=llm_planner,
                task_callback=task_callback,
                output_log_file=_log_file,
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
