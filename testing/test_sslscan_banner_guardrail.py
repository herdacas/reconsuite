#!/usr/bin/env python3
"""Test für den BUG-25-Nachtrag: sslscan-Eigenbanner-Fix in _value_grounding_guardrail.

Live bestätigt (2026-09-12, example.com full, trace_example.com_20260912_040746.json):
der reine Prompt-Hinweis reichte NICHT — der Report übernahm sslscans Eigenbanner
("Version: 2.1.2 / OpenSSL 3.0.13") erneut als angebliche Ziel-TLS-Version, in
BEIDEN Sektionen (Confirmed Findings + Detected Technologies). Dieser Test spielt
GENAU diese echten Daten nach (Reject-Kontrolle) + eine Positivkontrolle mit
echten sslscan-Cipher-Daten (Accept, kein Fehlalarm).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from tools.trace import run_trace  # noqa: E402
from tasks import _value_grounding_guardrail  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# Echter sslscan-Rohoutput aus diesem Live-Lauf (trace_example.com_20260912_040746.json,
# seq 7) — Cloudflare terminiert TLS, sslscan liefert NUR seinen eigenen Banner,
# keine echten Cipher-/Zertifikatsdaten gegen das Ziel.
REAL_SSLSCAN_BANNER_ONLY = "Version: \x1b[32m2.1.2\x1b[0m\nOpenSSL 3.0.13 30 Jan 2024\n\x1b[0m"

# ─── Reject-Kontrolle: echter fabrizierter Report-Text aus diesem Lauf ────────
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(["sslscan", "example.com", "--no-failed"], REAL_SSLSCAN_BANNER_ONLY, 0.01)

fabricated_report = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|-------|------|-------------|------|----------|
| tcp | 443 | OpenSSL 3.0.13 detected | sslscan | 13 |

## Detected Technologies
sslscan → OpenSSL 3.0.13
"""

ok, feedback = _value_grounding_guardrail(fabricated_report)
check(f"Reject: sslscan-Eigenbanner wird NICHT mehr als Ziel-Version akzeptiert (ok={ok})", ok is False)
if not ok:
    print(f"       Feedback: {feedback[:200]}")

run_trace.reset()

# ─── Positivkontrolle: echte sslscan-Cipher-/Zertifikatsdaten (kein Banner-Fall) ───
run_trace.activate("example.com", "test", "full", ["blue"])
REAL_SSLSCAN_WITH_DATA = (
    "Version: 2.1.2\nOpenSSL 3.0.13 30 Jan 2024\n\n"
    "Connected to 93.184.216.34\n\n"
    "Testing SSL server example.com on port 443\n\n"
    "  TLS renegotiation:\n"
    "Session renegotiation not supported\n\n"
    "  TLS Web Server Authentication\n"
    "RSA Key Strength:    2048\n\n"
    "Subject:  example.com\n"
    "Not valid after:  2027-01-15\n"
)
run_trace.record_execution(["sslscan", "example.com", "--no-failed"], REAL_SSLSCAN_WITH_DATA, 0.5)

clean_report = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|-------|------|-------------|------|----------|
| tcp | 443 | RSA Key Strength 2048 | sslscan | 1 |

## Detected Technologies
sslscan → RSA 2048
"""
ok2, feedback2 = _value_grounding_guardrail(clean_report)
check(f"Accept: echte sslscan-Scan-Daten (nicht der Banner) werden weiterhin akzeptiert (ok={ok2})", ok2 is True)

run_trace.reset()

# ─── Negativkontrolle: Positivkontrolle für andere Tools bleibt unberührt ─────
run_trace.activate("example.com", "test", "full", ["blue"])
run_trace.record_execution(["nmap", "example.com"], "443/tcp open  https\nOpenSSH 9.6p1 detected", 1.0)
clean_report2 = """## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|-------|------|-------------|------|----------|
| tcp | 443 | OpenSSH 9.6p1 detected | nmap | 1 |
"""
ok3, _ = _value_grounding_guardrail(clean_report2)
check(f"Accept: nicht-sslscan-Tools unverändert (kein Banner-Strip angewendet) (ok={ok3})", ok3 is True)

run_trace.reset()

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
