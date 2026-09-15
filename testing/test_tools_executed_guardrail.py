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
from tasks import _tools_executed_guardrail, BlueOutput, RedScanOutput  # noqa: E402

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

# --- Reproduktion Validierungs-Corpus-Backlog §5.1/5.2 (2026-09-15) ---
# corpus/fixtures/example-com/scanner_trace.json, Phase red_scan: tool_calls=[]
# (0 echte Calls), aber open_ports/vulnerabilities/targeted_findings/tools_executed
# sind 1:1 blue's Werte. Erwartung: deterministisch geleert, kein Reject/Retry.
run_trace.activate("example.com", "test", "full", ["red_scan"])
rso = RedScanOutput(
    targeted_findings=["OpenSSL 3.0.13"],
    tools_executed=["nmap_scanner", "httpx_prober", "whatweb_fingerprint",
                     "sslscan_tls", "nikto_scanner"],
    open_ports=[2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 80, 443, 8080, 8443],
    vulnerabilities=["Missing X-Frame-Options header on HTTPS endpoint."],
    analysis="x",
)
ok5, out5 = _tools_executed_guardrail(FakeTaskOutput(rso, "raw"))
check(f"Accept ohne Reject bei red_scan+0-Calls (ok={ok5})", ok5 is True)
check("open_ports geleert", rso.open_ports == [])
check("vulnerabilities geleert", rso.vulnerabilities == [])
check("targeted_findings geleert", rso.targeted_findings == [])
check("tools_executed geleert", rso.tools_executed == [])
run_trace.reset()

# --- Negativkontrolle: red_scan MIT echtem Tool-Call behält seine Felder ---
run_trace.activate("example.com", "test", "full", ["red_scan"])
run_trace.record_execution(["nuclei", "-u", "example.com"], "critical: CVE-2024-0001", 1.0)
rso2 = RedScanOutput(
    targeted_findings=["CVE-2024-0001 confirmed via nuclei"],
    tools_executed=["nuclei_vulnerability_scanner"],
    open_ports=[443],
    vulnerabilities=["CVE-2024-0001"],
    analysis="x",
)
ok6, _ = _tools_executed_guardrail(FakeTaskOutput(rso2, "raw"))
check(f"Accept bei red_scan+echtem Call, Felder bleiben (ok={ok6})", ok6 is True)
check("targeted_findings bleibt erhalten (echter Call)", rso2.targeted_findings == ["CVE-2024-0001 confirmed via nuclei"])
check("open_ports bleibt erhalten (echter Call)", rso2.open_ports == [443])
run_trace.reset()

# --- Negativkontrolle: blue mit 0 Calls wird NICHT von der neuen Logik erfasst ---
# (kein 'targeted_findings'-Feld auf BlueOutput -> is_red_scan=False; in der Praxis
# unerreichbar dank _tool_call_guardrail auf blue, hier zur Absicherung direkt getestet)
run_trace.activate("example.com", "test", "full", ["blue"])
bo5 = BlueOutput(tools_executed=["nmap_scanner"], open_ports=[443], vulnerabilities=["x"], analysis="x")
ok7, _ = _tools_executed_guardrail(FakeTaskOutput(bo5, "raw"))
check(f"blue+0-Calls bleibt unverändert von der red_scan-Logik (ok={ok7})", ok7 is True)
check("blue.open_ports unangetastet (kein targeted_findings-Feld -> nicht red_scan)", bo5.open_ports == [443])
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
