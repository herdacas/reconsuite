#!/usr/bin/env python3
"""Test für _tools_executed_guardrail (blue/red_scan) — 2026-09-12.

Live gefunden (www.cloudflare.com web, Test-Matrix-Nachtrag,
trace_www.cloudflare.com_20260912_051855.json): BlueOutput.tools_executed
nannte ['wafw00f', 'httpx_prober'], obwohl die blue-Task nur EINEN echten
Tool-Call machte (httpx). 'httpx_prober' ist legitim (CrewAI-Tool-Klassenname,
Präfix-Match nötig) — 'wafw00f' ist komplett erfunden, kein Call dazu im Trace.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from tools.trace import run_trace  # noqa: E402
from tasks import _tools_executed_guardrail, BlueOutput  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


class FakeTaskOutput:
    def __init__(self, pydantic, raw):
        self.pydantic = pydantic
        self.raw = raw


# --- Reject: der echte cloudflare.com-Fall ---
run_trace.activate("www.cloudflare.com", "test", "web", ["blue"])
run_trace.record_execution(["httpx", "www.cloudflare.com"], "Server: cloudflare", 0.5)
bo = BlueOutput(tools_executed=["wafw00f", "httpx_prober"], open_ports=[443], analysis="x")
ok, feedback = _tools_executed_guardrail(FakeTaskOutput(bo, "raw"))
check(f"Reject: 'wafw00f' ohne echten Call wird erkannt (ok={ok})", ok is False)
run_trace.reset()

# --- Accept: nur echte Tools, per Präfix-Match erkannt (Tool-Klassennamen) ---
run_trace.activate("example.com", "test", "web", ["blue"])
run_trace.record_execution(["httpx", "example.com"], "Server: nginx", 0.5)
run_trace.record_execution(["nmap", "example.com"], "443/tcp open", 1.0)
bo2 = BlueOutput(tools_executed=["httpx_prober", "nmap_scanner"], open_ports=[443], analysis="x")
ok2, _ = _tools_executed_guardrail(FakeTaskOutput(bo2, "raw"))
check(f"Accept: Präfix-Match echter Tools, kein Fehlalarm (ok={ok2})", ok2 is True)
run_trace.reset()

# --- Skip: leeres tools_executed (nichts zu prüfen) ---
run_trace.activate("example.com", "test", "web", ["blue"])
bo3 = BlueOutput(tools_executed=[], open_ports=[], analysis="x")
ok3, _ = _tools_executed_guardrail(FakeTaskOutput(bo3, "raw"))
check(f"Skip: leeres tools_executed wird nicht geprüft (ok={ok3})", ok3 is True)
run_trace.reset()

# --- Skip: pydantic=None (Guardrail-Retry-Pfad, kein Crash) ---
ok4, _ = _tools_executed_guardrail(FakeTaskOutput(None, "raw text"))
check(f"Skip: pydantic=None crasht nicht (ok={ok4})", ok4 is True)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
