#!/usr/bin/env python3
"""
check_agent.py — Testet einen einzelnen Agent mit einem simplen Task.
Zeigt ob CrewAI + AgentExecutor + LLM zusammenarbeiten.

Usage:
    python3 debugging/check_agent.py [research|blue|red]
    Default: research
"""
import sys, time, os, warnings
sys.path.insert(0, "agentscanit")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")

AGENT_NAME = sys.argv[1] if len(sys.argv) > 1 else "research"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "testphp.vulnweb.com"

warnings.filterwarnings("ignore")

from crewai import Task, Crew, Process
from config import EMBED_BASE_URL, EMBED_MODEL

# Embedder identisch zu crew.py — verhindert ChromaDB-Konflikt bei Knowledge Sources
_embedder = {
    "provider": "ollama",
    "config": {
        "url": f"{EMBED_BASE_URL}/api/embeddings",
        "model_name": EMBED_MODEL,
    },
}

if AGENT_NAME == "research":
    from agents import research_agent as agent
    task_desc = f"Run dig and whois on {TARGET}. Return a short summary of what you found."
elif AGENT_NAME == "blue":
    from agents import blue_agent as agent
    task_desc = f"Run ping and nmap on {TARGET}. Return a short summary of open ports."
elif AGENT_NAME == "red":
    from agents import red_agent as agent
    task_desc = f"Search searchsploit for 'Apache 2.4'. Return any CVEs found."
else:
    print(f"Unknown agent: {AGENT_NAME}. Use: research, blue, red")
    sys.exit(1)

task = Task(
    description=task_desc,
    expected_output="A short factual summary (2-3 sentences).",
    agent=agent,
)

crew = Crew(
    agents=[agent],
    tasks=[task],
    process=Process.sequential,
    embedder=_embedder,
    verbose=True,
)

print(f"\n=== Single Agent Test: {AGENT_NAME}_agent on {TARGET} ===\n")
t0 = time.time()
try:
    result = crew.kickoff(inputs={"target": TARGET})
    elapsed = time.time() - t0
    print(f"\n✓  Completed in {elapsed:.1f}s")
    print(f"   Result: {str(result)[:300]}")
except Exception as e:
    elapsed = time.time() - t0
    print(f"\n✗  Failed after {elapsed:.1f}s: {e}")
