#!/usr/bin/env python3
"""Test für das entzweideutigte Exploitable-Label im Risk Score (2026-09-19,
Output-Qualitäts-Fix Punkt 5).

Live gefunden (pentest-ground.com-Scan, Output-Qualitäts-Review):
risk_score_*.md zeigte "Exploitable: ✓ Ja", obwohl RedOutput.exploitable_
findings komplett leer war (kein PoC-Beleg) — has_exploitable wurde nur durch
nicht-leere red.cve_references gesetzt (flow.py::route_results()), nicht durch
tatsächlich verifizierte Exploits. Ein Leser konnte das leicht als "es gibt
einen bestätigten Exploit" fehlinterpretieren.

Fix: neues, getrenntes Feld RiskState.poc_verified — True nur wenn irgendeine
Task's 'exploitable_findings' nicht leer ist. has_exploitable UND die
Score-Berechnung (exploit_mul) bleiben unverändert (reines Label/Rendering,
keine Logikänderung).

Reproduktion mit den ECHTEN pentest-ground.com-Rohdaten dieser Session (keine
Synthetik) — genau der Fall, der den Fix motiviert hat.
"""
import sys
from pathlib import Path

_SUITE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SUITE_DIR))

import risk_scorer.risk_flow as rf  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


_REAL_CREW_JSON = _SUITE_DIR / "logs" / "crew_pentest-ground.com_20260919_042517.json"

if _REAL_CREW_JSON.exists():
    flow = rf.RiskFlow()
    flow.state.scan_json_path = str(_REAL_CREW_JSON)
    flow.state.nvd_results = []
    flow.state.has_exploitable = True  # wie vom Flow-Level übergeben (red_cves non-empty)
    flow.load_data()

    check("Reproduktion: has_exploitable bleibt True (CVE-Treffer — unverändertes Verhalten)",
          flow.state.has_exploitable is True)
    check("Reproduktion: poc_verified ist False (die echten Rohdaten hatten "
          "exploitable_findings=[] — genau die Zweideutigkeit, die den Fix motiviert hat)",
          flow.state.poc_verified is False)
else:
    print("[SKIP] pentest-ground.com-Session-Datei nicht gefunden — Reproduktion übersprungen")


# --- Positivkontrolle: exploitable_findings NICHT leer -> poc_verified=True ---
import json
import tempfile

_fake_summary = {
    "target": "test-target.internal",
    "report": "",
    "tasks": {
        "red": {
            "cve_references": ["CVE-2099-00001"],
            "exploitable_findings": ["CVE-2099-00001 — verifizierter Exploit gefunden (searchsploit EDB-1: Test)"],
        },
    },
}
with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
    json.dump(_fake_summary, f)
    tmp_path = f.name

flow2 = rf.RiskFlow()
flow2.state.scan_json_path = tmp_path
flow2.state.nvd_results = []
flow2.state.has_exploitable = True
flow2.load_data()
check("Positivkontrolle: nicht-leere exploitable_findings -> poc_verified=True",
      flow2.state.poc_verified is True)

# --- Negativkontrolle: has_exploitable=False UND keine exploitable_findings -> beides False ---
_fake_summary_clean = {
    "target": "test-clean.internal",
    "report": "",
    "tasks": {
        "findings": {"cve_references": [], "exploitable_findings": []},
    },
}
with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
    json.dump(_fake_summary_clean, f)
    tmp_path_clean = f.name

flow3 = rf.RiskFlow()
flow3.state.scan_json_path = tmp_path_clean
flow3.state.nvd_results = []
flow3.state.has_exploitable = False
flow3.load_data()
check("Negativkontrolle: sauberer Scan ohne Findings -> has_exploitable=False, poc_verified=False",
      flow3.state.has_exploitable is False and flow3.state.poc_verified is False)

# --- Rendering-Check: beide Zeilen erscheinen getrennt im Markdown ---
flow3.calculate_score()
flow3.write_report()
with open(flow3.state.report_md_path, encoding="utf-8") as f:
    md = f.read()
check("Markdown enthält getrennte Zeilen 'CVE-Treffer (red-Task)' und 'PoC-verifiziert'",
      "CVE-Treffer (red-Task)" in md and "PoC-verifiziert" in md)

# --- JSON-Check: poc_verified als eigenes Feld vorhanden, exploitable-Feld unverändert ---
with open(flow3.state.report_json_path, encoding="utf-8") as f:
    data = json.load(f)
check("JSON enthält sowohl 'exploitable' (unverändert) als auch neues 'poc_verified'-Feld",
      "exploitable" in data and "poc_verified" in data and data["poc_verified"] is False)

import os
os.remove(tmp_path)
os.remove(tmp_path_clean)
os.remove(flow3.state.report_md_path)
os.remove(flow3.state.report_json_path)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
