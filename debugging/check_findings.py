#!/usr/bin/env python3
"""
check_findings.py — Isoliert die findings-Task (CVE Analysis) mit research_agent.

Reproduziert den Pipeline-Fehler "Agent execution ended without reaching a
final answer". Speist exakt den Kontext ein den findings_task in der Pipeline
bekommt: research-Output + (leeres) blue-Output.

Usage:
    python3 debugging/check_findings.py [empty|populated]
      empty     — blue fand keine Services (Default, reproduziert Pipeline)
      populated — blue fand nginx/PHP (Gegenprobe)
"""
import sys, os, time, warnings
sys.path.insert(0, "agentscanit")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
warnings.filterwarnings("ignore")

MODE = sys.argv[1] if len(sys.argv) > 1 else "empty"
TARGET = "testphp.vulnweb.com"

from crewai import Task, Crew, Process
from config import EMBED_BASE_URL, EMBED_MODEL
from agents import research_agent
from tasks import FindingsOutput, _cve_trace_guardrail, make_tasks

_embedder = {"provider": "ollama",
             "config": {"url": f"{EMBED_BASE_URL}/api/embeddings", "model_name": EMBED_MODEL}}

# Realer research-Output aus dem Checkpoint
RESEARCH_CTX = """RESEARCH RESULTS (prior task):
{
  "target_type": "domain",
  "summary": "The domain testphp.vulnweb.com resolves to 44.228.249.3. WHOIS returned no record.",
  "subdomains": [],
  "technologies": [],
  "osint_notes": ["A record (dig) returned 44.228.249.3", "WHOIS no match"]
}"""

if MODE == "empty":
    BLUE_CTX = """BLUE RESULTS (prior task):
{
  "tools_executed": ["ping_check", "nmap_scanner", "naabu_port_scanner", "curl_http_headers", "httpx_prober"],
  "open_ports": [],
  "services": {},
  "vulnerabilities": [],
  "analysis": "Host does not respond to ICMP. Nmap reports host down. No open ports, no services identified."
}"""
else:
    BLUE_CTX = """BLUE RESULTS (prior task):
{
  "tools_executed": ["nmap_scanner", "httpx_prober", "whatweb"],
  "open_ports": [80, 443],
  "services": {"80": "nginx 1.19.0", "443": "nginx 1.19.0", "app": "PHP 5.6.40"},
  "vulnerabilities": [],
  "analysis": "Host runs nginx 1.19.0 and PHP 5.6.40 on ports 80/443."
}"""

# REAL findings-Task-Beschreibung aus make_tasks() — kein Shortcut.
# Kontext (research+blue) wird angehängt da wir die context=[] Tasks nicht mitlaufen lassen.
_real_findings = make_tasks()["findings"]
FINDINGS_DESC = (
    _real_findings.description.replace("{target}", TARGET).replace("{objective}", "CVE analysis")
    + f"\n\n=== KONTEXT AUS VORHERIGEN TASKS ===\n{RESEARCH_CTX}\n\n{BLUE_CTX}"
)

task = Task(
    description=FINDINGS_DESC,
    expected_output=_real_findings.expected_output,
    output_pydantic=FindingsOutput,
    guardrails=[_cve_trace_guardrail],
    guardrail_max_retries=2,
    agent=research_agent,
)

crew = Crew(agents=[research_agent], tasks=[task], process=Process.sequential,
            embedder=_embedder, verbose=True)

print(f"\n=== check_findings.py  mode={MODE}  agent=research (15 tools) ===\n")
t0 = time.time()
try:
    result = crew.kickoff(inputs={"target": TARGET, "objective": "CVE analysis"})
    print(f"\n✓  Completed in {time.time()-t0:.1f}s")
    print(f"   Result raw: {str(result)[:400]}")
    if hasattr(result, "tasks_output") and result.tasks_output:
        po = getattr(result.tasks_output[0], "pydantic", None)
        print(f"   Pydantic: {po}")
except Exception as e:
    import traceback
    print(f"\n✗  Failed after {time.time()-t0:.1f}s")
    print(f"   {type(e).__name__}: {str(e)[:300]}")
    print("   --- traceback tail ---")
    print("\n".join(traceback.format_exc().splitlines()[-12:]))
