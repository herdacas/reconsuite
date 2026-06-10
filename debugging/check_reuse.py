#!/usr/bin/env python3
"""
check_reuse.py — Testet ob research_agent bei ZWEITER Verwendung in einer Crew
fehlschlägt ("Agent execution ended without reaching a final answer").

Pipeline: research_agent läuft als Task 1 (research) UND Task 3 (findings).
Hypothese: Agent-Executor-Reuse über zwei Tasks korrumpiert den State.

Dieser Test: research_agent → Task A (research-style) → Task B (findings-style),
beide im selben Crew, sequential. context verkettet.

Usage:
    python3 debugging/check_reuse.py
"""
import sys, os, time, warnings
sys.path.insert(0, "agentscanit")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
warnings.filterwarnings("ignore")

TARGET = "testphp.vulnweb.com"

from crewai import Task, Crew, Process
from config import EMBED_BASE_URL, EMBED_MODEL
from agents import research_agent
from tasks import FindingsOutput, ResearchOutput, _cve_trace_guardrail, _tool_call_guardrail

_embedder = {"provider": "ollama",
             "config": {"url": f"{EMBED_BASE_URL}/api/embeddings", "model_name": EMBED_MODEL}}

# Task A: research (wie Pipeline-Task 1) — research_agent's erste Verwendung
task_a = Task(
    description=(
        f"Ziel: {TARGET}\n"
        "Führe passive Recon durch: dig und whois auf das Ziel. "
        "Gib target_type, summary, subdomains, technologies, osint_notes zurück."
    ),
    expected_output="Strukturierte Recon-Ergebnisse.",
    output_pydantic=ResearchOutput,
    guardrails=[_tool_call_guardrail],
    agent=research_agent,
)

# Task B: findings (wie Pipeline-Task 3) — research_agent's ZWEITE Verwendung
task_b = Task(
    description=(
        f"Ziel: {TARGET} | Objective: CVE analysis\n\n"
        "Extrahiere aus den vorherigen Ergebnissen Service-Versionen und bekannte CVEs. "
        "Wenn Services bekannt: nvd_cve_search + searchsploit pro Service. "
        "Trage in cve_references nur tool-bestätigte CVE-IDs ein."
    ),
    expected_output="Service-Versionen, CVE-IDs, faktische Zusammenfassung.",
    output_pydantic=FindingsOutput,
    guardrails=[_cve_trace_guardrail],
    guardrail_max_retries=2,
    agent=research_agent,
    context=[task_a],
)

crew = Crew(agents=[research_agent], tasks=[task_a, task_b],
            process=Process.sequential, embedder=_embedder, verbose=True)

print(f"\n=== check_reuse.py  research_agent ×2 (research → findings) ===\n")
t0 = time.time()
try:
    result = crew.kickoff(inputs={"target": TARGET})
    print(f"\n✓  BOTH tasks completed in {time.time()-t0:.1f}s")
    for i, to in enumerate(getattr(result, "tasks_output", []) or []):
        print(f"   Task {i}: {str(getattr(to,'raw',''))[:150]}")
except Exception as e:
    import traceback
    print(f"\n✗  Failed after {time.time()-t0:.1f}s")
    print(f"   {type(e).__name__}: {str(e)[:300]}")
    print("   --- traceback tail ---")
    print("\n".join(traceback.format_exc().splitlines()[-15:]))
