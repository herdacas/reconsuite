#!/usr/bin/env python3
"""
check_tools.py — Führt jedes Tool einzeln aus und misst Laufzeit.
Zeigt welche Tools hängen, timeout-en oder fehlschlagen.

Usage:
    python3 debugging/check_tools.py [target]
    Default target: testphp.vulnweb.com
"""
import sys, time, os
sys.path.insert(0, "agentscanit")
TARGET = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")

from tools import (
    ping_tool, nmap_tool, naabu_tool, httpx_tool, whatweb_tool,
    curl_tool, nikto_tool, sslscan_tool, testssl_tool, nuclei_tool,
    ffuf_tool, enum4linux_tool,
    ddg_search_tool, subfinder_tool, dnsrecon_tool, dig_tool,
    whois_tool, nvd_tool,
)

BLUE_TOOLS = [
    ("ping",       ping_tool,       TARGET),
    ("nmap",       nmap_tool,       TARGET),
    ("naabu",      naabu_tool,      TARGET),
    ("httpx",      httpx_tool,      TARGET),
    ("whatweb",    whatweb_tool,    f"http://{TARGET}"),
    ("curl",       curl_tool,       f"http://{TARGET}"),
    ("nikto",      nikto_tool,      TARGET),
    ("sslscan",    sslscan_tool,    TARGET),
    ("testssl",    testssl_tool,    TARGET),
    ("nuclei",     nuclei_tool,     TARGET),
    ("ffuf",       ffuf_tool,       f"http://{TARGET}/FUZZ"),
    ("enum4linux", enum4linux_tool, TARGET),
]

RESEARCH_TOOLS = [
    ("dig",        dig_tool,        TARGET),
    ("whois",      whois_tool,      TARGET),
    ("dnsrecon",   dnsrecon_tool,   TARGET),
    ("subfinder",  subfinder_tool,  TARGET),
    ("ddg_search", ddg_search_tool, f"site:{TARGET}"),
    ("nvd",        nvd_tool,        "Apache"),
]

def run_tool(name, tool, arg):
    t0 = time.time()
    try:
        result = tool._run(arg)
        elapsed = time.time() - t0
        lines = len((result or "").splitlines())
        preview = (result or "NO OUTPUT")[:80].replace("\n", " ")
        if "TOOL_ERROR" in (result or "") or "timeout" in (result or "").lower():
            status = "⚠"
        else:
            status = "✓"
        print(f"  {status}  {name:12s}  {elapsed:6.1f}s  {lines:4d} lines  {preview}")
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  ✗  {name:12s}  {elapsed:6.1f}s  ERROR: {str(e)[:100]}")

print(f"\n=== Tool Execution Test — Target: {TARGET} ===\n")
print("--- Blue Agent Tools (Active Scanning) ---")
for name, tool, arg in BLUE_TOOLS:
    run_tool(name, tool, arg)

print("\n--- Research Agent Tools (OSINT) ---")
for name, tool, arg in RESEARCH_TOOLS:
    run_tool(name, tool, arg)

print("\n=== Done ===\n")
