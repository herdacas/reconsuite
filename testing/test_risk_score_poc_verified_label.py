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

NACHTRAG (2026-09-19, Live-Verifikation scanme.nmap.org): der erste Fix-
Entwurf hatte selbst einen Bug — er prüfte auf task_data.get('exploitable_
findings') (die volle Liste), die agentscanit/main.py::_save_outputs() aber
NIE nach workflow_last.json/crew_*.json schreibt (nur den abgeleiteten
'exploitable_findings_count'). Der pentest-ground.com-Fall allein deckte das
nicht auf, weil dort count=0 war — der Bug UND der korrekte Fix liefern
zufällig dasselbe Ergebnis (False) für count=0. Erst der Live-Scan gegen
scanme.nmap.org (5 echte exploitable_findings, count=5) zeigte den Fehler:
poc_verified blieb fälschlich False. Gefixt: Prüfung auf
exploitable_findings_count > 0. Zweiter Reproduktionsblock unten mit den
echten scanme.nmap.org-Rohdaten deckt genau diesen Fall jetzt ab.
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

_REAL_CREW_JSON_2 = _SUITE_DIR / "logs" / "crew_scanme.nmap.org_20260919_062209.json"

if _REAL_CREW_JSON_2.exists():
    flow_sc = rf.RiskFlow()
    flow_sc.state.scan_json_path = str(_REAL_CREW_JSON_2)
    flow_sc.state.nvd_results = []
    flow_sc.state.has_exploitable = True
    flow_sc.load_data()

    check("Reproduktion (scanme.nmap.org, deckt den echten Bug auf): "
          "poc_verified ist True (red-Task hatte 5 echte exploitable_findings)",
          flow_sc.state.poc_verified is True)
else:
    print("[SKIP] scanme.nmap.org-Session-Datei nicht gefunden — zweite Reproduktion übersprungen")


# --- Positivkontrolle: exploitable_findings_count > 0 -> poc_verified=True ---
# WICHTIG: die reale Persistenz-Schicht (agentscanit/main.py::_save_outputs())
# schreibt NIE die volle 'exploitable_findings'-Liste nach workflow_last.json/
# crew_*.json — nur 'exploitable_findings_count' (Integer, aus len(pd.
# exploitable_findings) abgeleitet). Ein erster Testentwurf nutzte fälschlich
# einen literalen 'exploitable_findings'-Listen-Key (unrealistische Mock-Form)
# und hätte damit einen echten Bug verdeckt — bei der Live-Verifikation
# (2026-09-19, scanme.nmap.org, 5 echte exploitable_findings) zeigte
# poc_verified fälschlich "Nein", weil der Code auf genau diesen nie
# existierenden Listen-Key prüfte. Gefixt: Prüfung auf exploitable_findings_
# count > 0. Dieser Test bildet jetzt die ECHTE Datenform nach.
import json
import tempfile

_fake_summary = {
    "target": "test-target.internal",
    "report": "",
    "tasks": {
        "red": {
            "cve_references": ["CVE-2099-00001"],
            "exploitable_findings_count": 1,
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
check("Positivkontrolle: exploitable_findings_count > 0 -> poc_verified=True "
      "(reale Datenform, kein nie existierender Listen-Key)",
      flow2.state.poc_verified is True)

# --- Negativkontrolle: has_exploitable=False UND keine exploitable_findings -> beides False ---
_fake_summary_clean = {
    "target": "test-clean.internal",
    "report": "",
    "tasks": {
        "findings": {"cve_references": [], "exploitable_findings_count": 0},
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
