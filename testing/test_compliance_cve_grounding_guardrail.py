#!/usr/bin/env python3
"""Test für den compliance-CVE-Grounding-Guardrail (2026-09-19, Output-
Qualitäts-Fix Punkt 3).

Live gefunden (pentest-ground.com-Scan, Output-Qualitäts-Review): der
compliance_agent nannte CVE-2023-44487, CVE-2024-31079(/80/81), CVE-2021-23017,
CVE-2020-11724, CVE-2019-20372 für nginx — obwohl nvd_cpe_lookup für BEIDE
nginx-Versionen explizit "Keine CVEs" zurückgegeben hatte (reine Trainings-
daten-Erfindung), plus einen Zahlendreher (CVE-2021-32761 statt echtem
CVE-2021-32762). Anders als findings/red hatte der compliance-Task bisher
KEINEN CVE-Guardrail.

Reproduktion mit dem ECHTEN fabrizierten compliance_pentest-ground.com_
20260919_043050.md dieser Session (keine Synthetik) + der echten trusted-Menge
aus crew_pentest-ground.com_20260919_042517.json.

Bekannte, akzeptierte Grenze (dokumentiert, kein Fehlalarm): Kurzschreibweisen
wie "CVE-2024-31079/31080/31081" werden nur beim ERSTEN vollständigen Muster
("CVE-2024-31079") erkannt — die Suffix-Fortsetzungen "/31080/31081" sind kein
eigenständiges CVE-YYYY-NNNNN-Muster und werden vom Regex nicht separiert.
Das ist eine bewusste Vereinfachung (Aufwand/Nutzen), kein False-Negative im
Sinne fehlender Erkennung EINES vollständig geschriebenen CVE-Strings.
"""
import re
import sys
from pathlib import Path

_SUITE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SUITE_DIR))

import compliance_agent.compliance_flow as cf  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


class FakeOutput:
    def __init__(self, raw):
        self.raw = raw


_REAL_COMPLIANCE_MD = _SUITE_DIR / "logs" / "compliance_pentest-ground.com_20260919_043050.md"
_REAL_CREW_JSON = _SUITE_DIR / "logs" / "crew_pentest-ground.com_20260919_042517.json"

if _REAL_COMPLIANCE_MD.exists() and _REAL_CREW_JSON.exists():
    import json

    real_text = _REAL_COMPLIANCE_MD.read_text(encoding="utf-8")
    crew_data = json.loads(_REAL_CREW_JSON.read_text(encoding="utf-8"))
    trusted = set()
    for task_name, task_data in crew_data.get("tasks", {}).items():
        for c in task_data.get("cve_references", []) or []:
            trusted.add(c.upper())
    check("Reproduktion: echte trusted-Menge aus crew.json geladen (40 CVEs erwartet)",
          len(trusted) == 40)

    guardrail = cf._make_cve_grounding_guardrail(trusted)
    out = FakeOutput(real_text)

    ok1, result1 = guardrail(out)
    _expected_fabricated = {"CVE-2023-44487", "CVE-2024-31079", "CVE-2021-23017",
                             "CVE-2020-11724", "CVE-2019-20372", "CVE-2021-32761"}
    check("1. Versuch: Reject, Feedback nennt alle 6 vollständig geschriebenen "
          "fabrizierten/falschen CVE-IDs",
          ok1 is False and all(c in result1 for c in _expected_fabricated))
    check("1. Versuch: der echte Text ist NOCH unverändert (kein Auto-Fix beim ersten Versuch)",
          out.raw == real_text)

    ok2, result2 = guardrail(out)
    check("2. Versuch: wird akzeptiert (True)", ok2 is True)
    for c in _expected_fabricated:
        check(f"2. Versuch: {c} im bereinigten Text markiert (nicht mehr unkommentiert)",
              f"{c} [nicht tool-bestätigt — entfernt]" in result2)
    # Echte, trace-verifizierte CVEs müssen unangetastet bleiben
    for c in ["CVE-2022-0543", "CVE-2023-38408", "CVE-2019-2725", "CVE-2020-14882"]:
        check(f"2. Versuch: echte CVE {c} bleibt UNVERÄNDERT im Text (kein Fehlalarm)",
              c in result2 and f"{c} [nicht tool-bestätigt" not in result2)
else:
    print("[SKIP] pentest-ground.com-Session-Dateien nicht gefunden — Reproduktion übersprungen")


# --- Positivkontrolle: sauberer Text, nur trusted CVEs -> kein Reject ---
guardrail_clean = cf._make_cve_grounding_guardrail({"CVE-2022-0543", "CVE-2023-38408"})
clean_text = "Redis 5.0.7 ist verwundbar (CVE-2022-0543). OpenSSH betroffen (CVE-2023-38408)."
ok_clean, result_clean = guardrail_clean(FakeOutput(clean_text))
check("Positivkontrolle: nur trusted CVEs -> kein Reject, Text unverändert",
      ok_clean is True and result_clean == clean_text)

# --- Negativkontrolle: Text ganz ohne CVE-Erwähnung -> No-Op ---
guardrail_none = cf._make_cve_grounding_guardrail({"CVE-2022-0543"})
no_cve_text = "Redis läuft ohne Authentifizierung — Konfigurationsfehler, keine CVE nötig."
ok_none, result_none = guardrail_none(FakeOutput(no_cve_text))
check("Negativkontrolle: Text ohne jede CVE-Erwähnung -> No-Op",
      ok_none is True and result_none == no_cve_text)

# --- Regressionscheck: leere trusted-Menge lehnt JEDE CVE ab (kein stiller Pass-Through) ---
guardrail_empty = cf._make_cve_grounding_guardrail(set())
ok_empty1, result_empty1 = guardrail_empty(FakeOutput("Betroffen: CVE-2022-0543."))
check("Regressionscheck: leere trusted-Menge -> 1. Versuch lehnt ab (kein blindes Akzeptieren)",
      ok_empty1 is False)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
