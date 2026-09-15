#!/usr/bin/env python3
"""Deterministische Tests für cve_filters.is_kev() — Negations-Fix (2026-09-12).

Kein CrewAI/Ollama nötig. Positiv- + Negativkontrolle.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cve_filters import is_kev  # noqa: E402

passed = 0
failed = 0


def check(name, cve, expected):
    global passed, failed
    result = is_kev(cve)
    ok = result == expected
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: is_kev={result} (erwartet {expected})")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Positivkontrolle: echte KEV-Formulierungen müssen weiterhin True liefern ---
check(
    "real KEV — exploited in the wild",
    {"description": "This vulnerability has been exploited in the wild since 2021."},
    True,
)
check(
    "real KEV — known to be exploited",
    {"description": "CISA has confirmed this CVE is known to be exploited by threat actors."},
    True,
)
check(
    "real KEV — actively exploited",
    {"description": "The flaw is actively exploited according to multiple vendor reports."},
    True,
)
check(
    "real KEV — negation in a DIFFERENT sentence should not suppress the match",
    {"description": "There is no patch available yet. This vulnerability is known to be exploited in the wild."},
    True,
)

# --- Negativkontrolle: Verneinung im selben Satz darf NICHT als KEV gewertet werden ---
check(
    "negation — not known to be exploited",
    {"description": "As of this writing, this vulnerability is not known to be exploited in the wild."},
    False,
)
check(
    "negation — no evidence of exploitation",
    {"description": "There is no evidence that this issue is being exploited in the wild."},
    False,
)
check(
    "negation — unlikely to be exploited",
    {"description": "This is unlikely to be actively exploited given the required access."},
    False,
)
check(
    "negative control — no KEV phrase at all",
    {"description": "A buffer overflow allows an attacker to crash the service."},
    False,
)
check(
    "negative control — empty description",
    {"description": ""},
    False,
)
check(
    "negative control — missing description key",
    {},
    False,
)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
