#!/usr/bin/env python3
"""
check_llm.py — LLM Connectivity + Native-FC Diagnose
Tests:
  A) OpenAI-compat (/v1) — 1 Tool
  B) Ollama-native (/api/chat) — 1 Tool (wie LiteLLM es sendet)
  C) Ollama-native — 15 Tools (wie research_agent es sendet)
  D) Ollama-native — 15 Tools + volles System-Prompt

Usage:
    python3 debugging/check_llm.py
"""
import sys, time, json
sys.path.insert(0, "agentscanit")

from config import ACTIVE_ANALYSIS, ACTIVE_RESEARCH, ACTIVE_BASE_URL, OLLAMA_API_KEY
from openai import OpenAI
import ollama as _ollama

BASE = ACTIVE_BASE_URL.rstrip("/")
oai  = OpenAI(base_url=f"{BASE}/v1", api_key=OLLAMA_API_KEY or "ollama")
olc  = _ollama.Client(host=BASE, headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"} if OLLAMA_API_KEY else {})

# ── Tool-Schemas ──────────────────────────────────────────────────────────────

ONE_TOOL = [{"type": "function", "function": {
    "name": "run_nmap", "description": "Run nmap",
    "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
}}]

# Simuliert research_agent: 15 Tools (wie in agents.py definiert)
TOOL_NAMES = ["ddg_search","theharvester","whois","dig","dnsrecon","subfinder",
              "sublist3r","amass","assetfinder","dnsx","katana","waybackurls",
              "gau","searchsploit","nvd_cve_search"]
FULL_TOOLS = [{"type": "function", "function": {
    "name": n, "description": f"Security reconnaissance tool: {n}",
    "parameters": {"type": "object", "properties": {
        "query": {"type": "string", "description": "Target or search query"},
    }, "required": ["query"]},
}} for n in TOOL_NAMES]

SYSTEM_PROMPT = (
    "You are an OSINT and Reconnaissance Specialist. "
    "Collect publicly available information about the target. "
    "Use tools to gather data. Only report tool-confirmed facts."
)
TASK_PROMPT = (
    "Perform passive reconnaissance on testphp.vulnweb.com. "
    "Use dig and whois first. Return a short JSON summary."
)

# ── Test-Funktionen ───────────────────────────────────────────────────────────

def test_oai(label, model, tools):
    t0 = time.time()
    try:
        resp = oai.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Use a tool on 127.0.0.1"}],
            tools=tools, tool_choice="auto",
            extra_body={"num_ctx": 16384, "keep_alive": "5m", "think": False},
            timeout=20,
        )
        elapsed = time.time() - t0
        has_tc = bool(getattr(resp.choices[0].message, "tool_calls", None))
        status = "✓" if has_tc else "⚠"
        print(f"  {status}  {label:40s}  {elapsed:5.1f}s  tool_call={'YES' if has_tc else 'NO (content='+repr((resp.choices[0].message.content or '')[:40])+')'}")
    except Exception as e:
        print(f"  ✗  {label:40s}  {time.time()-t0:5.1f}s  {str(e)[:100]}")


def test_ollama(label, model, tools, system=None):
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": TASK_PROMPT if system else "Use a tool on 127.0.0.1"})

    t0 = time.time()
    try:
        resp = olc.chat(
            model=model,
            messages=msgs,
            tools=tools,
            options={"num_ctx": 16384, "keep_alive": "5m"},
            think=False,
        )
        elapsed = time.time() - t0
        has_tc = bool(resp.message.tool_calls)
        status = "✓" if has_tc else "⚠"
        content = (resp.message.content or "")[:40]
        print(f"  {status}  {label:40s}  {elapsed:5.1f}s  tool_call={'YES' if has_tc else 'NO content='+repr(content)}")
    except Exception as e:
        print(f"  ✗  {label:40s}  {time.time()-t0:5.1f}s  {str(e)[:100]}")


# ── Ausgabe ───────────────────────────────────────────────────────────────────

print(f"\n=== LLM Diagnose  ({BASE}) ===")
print(f"  analysis: {ACTIVE_ANALYSIS}  |  research: {ACTIVE_RESEARCH}\n")

model = ACTIVE_ANALYSIS
print("--- A) OpenAI-compat (/v1) ---")
test_oai(f"{model} — 1 tool",  model, ONE_TOOL)
test_oai(f"{model} — 15 tools", model, FULL_TOOLS)

print("\n--- B) Ollama-native (/api/chat) ---")
test_ollama(f"{model} — 1 tool",                    model, ONE_TOOL)
test_ollama(f"{model} — 15 tools",                  model, FULL_TOOLS)
test_ollama(f"{model} — 15 tools + system prompt",  model, FULL_TOOLS, system=SYSTEM_PROMPT)

if ACTIVE_RESEARCH != ACTIVE_ANALYSIS:
    print(f"\n--- Research model: {ACTIVE_RESEARCH} ---")
    test_oai   (f"{ACTIVE_RESEARCH} — 15 tools", ACTIVE_RESEARCH, FULL_TOOLS)
    test_ollama(f"{ACTIVE_RESEARCH} — 15 tools", ACTIVE_RESEARCH, FULL_TOOLS)

print("\n=== Done ===\n")
