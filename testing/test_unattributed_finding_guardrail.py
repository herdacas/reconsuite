#!/usr/bin/env python3
"""Test für den Fix: 'Confirmed Findings'-Zeile mit KOMPLETT LEERER Tool-Spalte
wird jetzt als unbelegte Behauptung erkannt (_confirmed_findings_tool_guardrail).

Live bestätigt (2026-09-12, www.cloudflare.com web, Test-Matrix-Nachtrag):
'| Cloudflare | 443 | WAF/CDN detected: Cloudflare Edge network |  |  |' —
wafw00f wurde in der Session NIE aufgerufen, die Zeile hat aber auch KEINEN
falschen Tool-Namen zum Erkennen — sie hat GAR KEINEN. Wurde vorher übersprungen
('not tool_col' → continue), entging so beiden Grounding-Guardrails.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from tools.trace import run_trace  # noqa: E402
from tasks import _confirmed_findings_tool_guardrail  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Reject: der echte cloudflare.com-Fall (leere Tool-Spalte) ---
run_trace.activate("www.cloudflare.com", "test", "web", ["blue"])
run_trace.record_execution(["nmap", "www.cloudflare.com"], "443/tcp open https", 1.0)
real_report = """## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| Cloudflare | 443 | WAF/CDN detected: Cloudflare Edge network |  |  |
"""
ok, feedback = _confirmed_findings_tool_guardrail(real_report)
check(f"Reject: leere Tool-Spalte bei echter Datenzeile (ok={ok})", ok is False)
run_trace.reset()

# --- Accept: saubere Tabelle mit korrekt zugeordnetem Tool ---
run_trace.activate("example.com", "test", "web", ["blue"])
run_trace.record_execution(["nmap", "example.com"], "443/tcp open https", 1.0)
clean_report = """## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| tcp | 443 | open | nmap | 1 |
"""
ok2, _ = _confirmed_findings_tool_guardrail(clean_report)
check(f"Accept: saubere Tabelle, kein Fehlalarm (ok={ok2})", ok2 is True)
run_trace.reset()

# --- Negativkontrolle: Header-/Trennzeilen weiterhin korrekt als solche erkannt ---
run_trace.activate("example.com", "test", "web", ["blue"])
run_trace.record_execution(["nmap", "example.com"], "443/tcp open https", 1.0)
header_only_report = """## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
"""
ok3, _ = _confirmed_findings_tool_guardrail(header_only_report)
check(f"Accept: nur Header/Trennzeile, keine Datenzeile (ok={ok3})", ok3 is True)
run_trace.reset()

# --- Regression: originaler BUG-23-Fall (falscher Tool-Name statt leer) ---
run_trace.activate("rastede.de", "test", "full", ["red"])
run_trace.record_execution(["searchsploit", "--json", "Apache"], "ActiveMQ stuff", 1.0)
bug23_report = """## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| ActiveMQ | 8161 | Web Shell Upload | nuclei_vulnerability_scanner | 1 |
"""
ok4, _ = _confirmed_findings_tool_guardrail(bug23_report)
check(f"Regression BUG-23 (falscher Tool-Name) weiterhin erkannt (ok={ok4})", ok4 is False)
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
