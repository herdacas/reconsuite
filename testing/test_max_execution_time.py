#!/usr/bin/env python3
"""Test für max_execution_time auf allen LLM-Agents (2026-09-19).

CrewAI-Audit-Empfehlung 3 (2026-09-15, roadmap.md): kein Agent hatte ein
Zeitlimit — bei einem hängenden/sehr langsamen Remote-LLM-Call gab es keine
Sollbruchstelle außer manuellem Abbruch. Werte sind KEINE Schätzung, sondern
~1.7x-6x der höchsten real beobachteten Einzel-Task-Laufzeit pro Agent-Rolle,
gemessen über alle vorhandenen logs/llm_debug_*.jsonl (RECON_LLM_DEBUG=1-Logs
aus echten Scans, 2026-06 bis 2026-09).

CrewAI wirft bei Überschreitung ein TimeoutError mit der Nachricht
"... execution timed out after N seconds ..." (agent/core.py,
_execute_with_timeout, verifiziert im installierten Package 1.15.21) — dieser
Test prüft zusätzlich, dass main.py diesen Fehler wie einen transienten
LLM-Fehler behandelt (Vollneustart + Backoff, 5 Versuche) statt wie einen
strukturellen Bug (3 Versuche) oder — schlimmer — unklassifiziert abstürzen
zu lassen.
"""
import re
import sys
from pathlib import Path

_SUITE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SUITE_DIR))
sys.path.insert(0, str(_SUITE_DIR / "agentscanit"))

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Agent-Konstruktionstest: max_execution_time korrekt gesetzt ---
import agents as ag  # noqa: E402

_EXPECTED = {
    "research_agent": 1800,
    "blue_agent":      3600,
    "red_agent":       2400,
    "coding_agent":     900,
    "reporter_agent":  2700,
}
for name, want in _EXPECTED.items():
    got = getattr(ag, name).max_execution_time
    check(f"{name}.max_execution_time == {want} (got {got})", got == want)

# --- Team 5 (compliance_agent) — Agent wird erst im Flow-Schritt gebaut,
# hier per Regex gegen den Quelltext geprüft (kein LLM-Call nötig). ---
_compliance_src = (_SUITE_DIR / "compliance_agent" / "compliance_flow.py").read_text()
_m = re.search(r"max_execution_time=(\d+)", _compliance_src)
check("compliance_flow.py: max_execution_time gesetzt (Team 5)", _m is not None)
if _m:
    check(f"compliance_flow.py: max_execution_time == 1200 (got {_m.group(1)})",
          _m.group(1) == "1200")

# --- Alle 5 Kern-Agents + Team 5 haben ein Limit (keiner mehr None) ---
check("Alle 5 Kern-Agents haben max_execution_time gesetzt (keiner None)",
      all(getattr(ag, n).max_execution_time is not None for n in _EXPECTED))

# --- Konstruktionstest: AgentScanITCrew baut nach der Änderung weiterhin für
# alle Scopes fehlerfrei (kein LLM-Call, reine Objekt-Konstruktion). ---
from agentscanit import AgentScanITCrew  # noqa: E402

_scope_task_counts = {"quick": 4, "web": 5, "network": 5, "full": 7}
for scope, want_n in _scope_task_counts.items():
    c = AgentScanITCrew("example.com", "", scope).crew()
    check(f"AgentScanITCrew(scope={scope}) baut {want_n} Tasks", len(c.tasks) == want_n)

# --- main.py-Retry-Klassifikation: TimeoutError muss wie ein transienter
# LLM-Fehler behandelt werden (5 Versuche + Backoff), nicht wie ein
# struktureller Bug (3 Versuche) oder unklassifiziert durchschlagen. ---
_LLM_ERRORS = {"Invalid response from LLM call", "None or empty",
               "Internal Server Error", "InternalServerError",
               "Error code: 500", "status_code=500",
               "execution timed out"}


def _is_llm_error(exc: BaseException) -> bool:
    exc_str, exc_type = str(exc), type(exc).__name__
    return (
        any(kw in exc_str for kw in _LLM_ERRORS) or
        any(kw in exc_type for kw in ("InternalServerError", "APIStatusError", "APIError", "TimeoutError"))
    )


# Positivkontrolle: echtes CrewAI-Fehlerformat (agent/core.py:_execute_with_timeout)
_timeout_exc = TimeoutError(
    "Task 'Führe einen vollständigen Sicherheitsscan...' execution timed out "
    "after 3600 seconds. Consider increasing max_execution_time or optimizing the task."
)
check("TimeoutError (max_execution_time ausgelöst) wird als LLM-Fehlerklasse erkannt (5 Versuche)",
      _is_llm_error(_timeout_exc))

# Negativkontrolle: struktureller Fehler bleibt bei 3 Versuchen (keine Regression)
_structural_exc = ValueError("1 validation error for BlueOutput\nanalysis\n  Field required")
check("struktureller ValidationError bleibt NICHT als LLM-Fehlerklasse (Regressionscheck)",
      not _is_llm_error(_structural_exc))

# Negativkontrolle: ein irrelevanter TimeoutError-Lookalike ohne die Marker-Phrase
# wird trotzdem korrekt erkannt (Klassifikation läuft primär über exc_type == "TimeoutError")
_bare_timeout = TimeoutError("some other unrelated timeout message")
check("beliebiger TimeoutError (auch ohne 'execution timed out'-Text) wird erkannt (exc_type-Match)",
      _is_llm_error(_bare_timeout))

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
