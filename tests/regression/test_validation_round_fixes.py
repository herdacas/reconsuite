#!/usr/bin/env python3
"""tests/regression/test_validation_round_fixes.py — Regressionsfälle aus der
Validierungsrunde (debugging/VALIDATION_SPEC.md), 2026-09-12.

Zwei echte, per Oracle-gestütztem Corpus-Scoring gefundene Bugs in den heute
bereits geschriebenen Guardrails selbst (nicht im Scanner) — je ein Fall pro
Bug, mit den ECHTEN Rohdaten aus dem Corpus nachgestellt (corpus/fixtures/).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "agentscanit"))

from tools.trace import run_trace  # noqa: E402
from tasks import (  # noqa: E402
    _value_grounding_guardrail,
    _confirmed_findings_tool_guardrail,
    _tool_name_grounded,
)

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Bug 1: Case-Sensitivity — whois liefert Domains in GROSSBUCHSTABEN ---
# Echter Fall (corpus/fixtures/cloudflare-com): whois-Output enthält
# 'No match for "WWW.CLOUDFLARE.COM".', die Beobachtung zitiert
# 'www.cloudflare.com' (Kleinbuchstaben) — semantisch identisch, RFC 4343
# (Hostnamen sind case-insensitiv).
run_trace.activate("www.cloudflare.com", "test", "web", ["research"])
run_trace.record_execution(
    ["whois", "www.cloudflare.com"],
    'No match for "WWW.CLOUDFLARE.COM".\n>>> Last update of whois database ...',
    0.3,
)
report = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| WHOIS | - | No match for domain 'www.cloudflare.com' | whois | 1 |
"""
ok, feedback = _value_grounding_guardrail(report)
check(f"Bug 1 (case-insensitiv): whois-GROSSBUCHSTABEN vs. Beobachtung-Kleinbuchstaben wird jetzt akzeptiert (ok={ok})", ok is True)
run_trace.reset()

# --- Bug 2: Tool-Namen-Varianten in _confirmed_findings_tool_guardrail ---
# Echte Fälle: 'nuclei_vulnerability_scanner' (real: nuclei, corpus/fixtures/
# rastede-de) und 'nmap (step_1)' (real: nmap, corpus/fixtures/scanme-nmap-org).
check(
    "Bug 2a: 'nuclei_vulnerability_scanner' als Präfix-Variante von 'nuclei' erkannt",
    _tool_name_grounded("nuclei_vulnerability_scanner", {"nuclei"}),
)
check(
    "Bug 2b: 'nmap (step_1)' als führendes Wort vor Suffix erkannt",
    _tool_name_grounded("nmap (step_1)", {"nmap"}),
)
check(
    "Negativkontrolle: komplett falscher Tool-Name bleibt NICHT gegroundet",
    not _tool_name_grounded("metasploit_exploiter", {"nmap", "nuclei", "httpx"}),
)

run_trace.activate("rastede.de", "test", "full", ["red"])
run_trace.record_execution(["nuclei", "-tags", "cves"], "some real nuclei output", 1.0)
report2 = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| http | 443 | echte nuclei-Beobachtung | nuclei_vulnerability_scanner | 1 |
"""
ok2, _ = _confirmed_findings_tool_guardrail(report2)
check(f"Bug 2 E2E: Guardrail akzeptiert 'nuclei_vulnerability_scanner' jetzt (ok={ok2})", ok2 is True)
run_trace.reset()

# --- Regression: ein WIRKLICH nie gelaufenes Tool bleibt weiterhin ein Reject ---
run_trace.activate("rastede.de", "test", "full", ["red"])
run_trace.record_execution(["nuclei", "-tags", "cves"], "some real nuclei output", 1.0)
report3 = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| http | 8161 | Web Shell Upload | nikto_scanner | 1 |
"""
ok3, _ = _confirmed_findings_tool_guardrail(report3)
check(f"Regression: 'nikto_scanner' (nikto lief NIE) bleibt Reject (ok={ok3})", ok3 is False)
run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
