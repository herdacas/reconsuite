#!/usr/bin/env python3
"""Test für Team2/Team4-Parallelisierung im Master-Flow (2026-09-19).

CrewAI-Audit-Empfehlung 2 (2026-09-15, roadmap.md): `run_threat_intel` (Team 4)
hing im Flow-Graph künstlich an `run_interpret` (Team 2), obwohl beide nur
`scan_json_path` brauchen — keine echte Datenabhängigkeit. Fix (flow.py):
beide hören jetzt auf denselben Router-Trigger (`or_("full_analysis",
"cve_analysis")`), `run_compliance` wartet über `and_(run_interpret,
run_threat_intel)` auf beide statt nur auf `run_threat_intel`.

Verifiziert real über `ReconSuiteFlow.kickoff()` (echte CrewAI-Flow-Engine,
kein LLM/Netzwerk — die Team-Sub-Flows sind gemockt, echte Timing-Messung via
time.sleep()) für alle 3 Router-Ergebnisse:
  1. full_analysis: interpret + threat_intel müssen sich zeitlich ÜBERLAPPEN
     (Beweis für echte Parallelität, nicht nur korrekte Verdrahtung) UND
     compliance darf erst NACH BEIDEN starten.
  2. cve_analysis: threat_intel ist strukturell ein No-Op (has_exploitable=False),
     muss aber weiterhin laufen (damit and_() erfüllt wird) UND compliance
     muss trotzdem laufen (Regressionscheck für die alte sequenzielle Kopplung).
  3. clean: weder interpret noch threat_intel noch compliance laufen — nur
     skip_teams -> reporting (unverändertes Verhalten).

logs/workflow_last.json wird für die Testdauer überschrieben und danach exakt
wiederhergestellt (Backup/Restore), um keinen echten Scan-Zustand zu zerstören.
"""
import json
import os
import shutil
import sys
import time
from pathlib import Path

_SUITE_DIR = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, _SUITE_DIR)

import flow as f  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


LOG_DIR = f.LOG_DIR
WORKFLOW_LAST = os.path.join(LOG_DIR, "workflow_last.json")
SLEEP = 0.6  # genug um Overlap sicher von Zufalls-Jitter zu unterscheiden

events = []  # (name, "start"|"end", timestamp)


def _record(name, phase):
    events.append((name, phase, time.time()))


def _write_workflow_last(has_cves: bool, has_exploitable: bool, report_path: str):
    tasks = {
        "findings": {"cve_references": ["CVE-2024-0001"] if has_cves else []},
        "red": {
            "exploitable_findings_count": 1 if has_exploitable else 0,
            "exploitable_findings": ["fake:1234 — PoC-belegt"] if has_exploitable else [],
            "cve_references": [],
        },
    }
    with open(WORKFLOW_LAST, "w") as fh:
        json.dump({"report": report_path, "tasks": tasks}, fh)


def _fake_scan_run(target, objective, scope, log_llm=False):
    # Ersetzt agentscanit.main.run() — schreibt workflow_last.json direkt mit
    # den für den jeweiligen Testfall gewünschten cve/exploitable-Flags.
    _write_workflow_last(*_SCAN_CFG["cves_exploitable"], report_path=f"fake_report_{target}.md")


def _fake_interpret(scan_json_path):
    _record("interpret", "start")
    time.sleep(SLEEP)
    _record("interpret", "end")

    class _State:
        nvd_results = []

    class _Flow:
        state = _State()

    return _Flow()


def _fake_threatintel(scan_json_path):
    _record("threat_intel", "start")
    time.sleep(SLEEP)
    _record("threat_intel", "end")

    class _State:
        threat_summary = "fake threat summary"

    class _Flow:
        state = _State()

    return _Flow()


def _fake_compliance(scan_json_path):
    _record("compliance", "start")
    time.sleep(0.05)
    _record("compliance", "end")

    class _State:
        mapping_result = "fake mapping"

    class _Flow:
        state = _State()

    return _Flow()


def _fake_risk(scan_json_path, nvd_results, threat_intel_output, compliance_output, has_exploitable):
    _record("risk", "start")

    class _State:
        risk_score = 0.0
        risk_level = "NONE"

    class _Flow:
        state = _State()

    return _Flow()


def _fake_reporting(scan_target, scan_report_path, nvd_results):
    _record("reporting", "start")

    class _State:
        final_report_path = "fake_final_report.md"

    class _Flow:
        state = _State()

    return _Flow()


def _names_called():
    return {name for name, _, _ in events}


def _overlap(name_a, name_b):
    """True wenn sich die [start,end]-Intervalle von name_a und name_b überschneiden."""
    a_start = next(t for n, p, t in events if n == name_a and p == "start")
    a_end = next(t for n, p, t in events if n == name_a and p == "end")
    b_start = next(t for n, p, t in events if n == name_b and p == "start")
    b_end = next(t for n, p, t in events if n == name_b and p == "end")
    return a_start < b_end and b_start < a_end


def _started_after(name, after_name_end_max):
    a_start = next(t for n, p, t in events if n == name and p == "start")
    return a_start >= after_name_end_max


# --- Backup workflow_last.json (echten Scan-Zustand nicht zerstören) ---
_backup = None
if os.path.exists(WORKFLOW_LAST):
    _backup = WORKFLOW_LAST + ".bak_test_parallel"
    shutil.copy2(WORKFLOW_LAST, _backup)

_orig_scan_run = f._scan_main.run
_orig_interpret = f._interpret.run_interpret_flow
_orig_threatintel = f._threatintel.run_threatintel_flow
_orig_compliance = f._compliance.run_compliance_flow
_orig_risk = f._risk.run_risk_flow
_orig_reporting = f._reporting.run_reporting_flow

f._scan_main.run = _fake_scan_run
f._interpret.run_interpret_flow = _fake_interpret
f._threatintel.run_threatintel_flow = _fake_threatintel
f._compliance.run_compliance_flow = _fake_compliance
f._risk.run_risk_flow = _fake_risk
f._reporting.run_reporting_flow = _fake_reporting

_SCAN_CFG = {"cves_exploitable": (False, False)}

try:
    # ── Fall 1: full_analysis (has_exploitable=True) ──────────────────────
    events.clear()
    _SCAN_CFG["cves_exploitable"] = (True, True)
    f.run_flow("test-parallel-full.internal", "", "quick")

    check("full_analysis: interpret UND threat_intel wurden aufgerufen",
          {"interpret", "threat_intel"} <= _names_called())
    check("full_analysis: interpret/threat_intel überlappen sich zeitlich (echte Parallelität)",
          _overlap("interpret", "threat_intel"))
    _both_end = max(
        next(t for n, p, t in events if n == "interpret" and p == "end"),
        next(t for n, p, t in events if n == "threat_intel" and p == "end"),
    )
    check("full_analysis: compliance startet erst NACH BEIDEN (interpret+threat_intel)",
          _started_after("compliance", _both_end))
    check("full_analysis: risk + reporting liefen ebenfalls",
          {"risk", "reporting"} <= _names_called())

    # ── Fall 2: cve_analysis (has_cve_findings=True, has_exploitable=False) ─
    events.clear()
    _SCAN_CFG["cves_exploitable"] = (True, False)
    f.run_flow("test-parallel-cve.internal", "", "quick")

    check("cve_analysis: interpret lief (echte CVE-Analyse)",
          "interpret" in _names_called())
    check("cve_analysis: threat_intel-Team-Flow wurde NICHT aufgerufen (korrekter No-Op-Zweig, has_exploitable=False)",
          "threat_intel" not in _names_called())
    check("cve_analysis: compliance lief TROTZDEM (and_() wird auch vom No-Op-Rückgabepfad erfüllt — "
          "Regression gegen die alte Sequenz-Kopplung, die hier vorher funktionierte)",
          "compliance" in _names_called())

    # ── Fall 3: clean (weder CVEs noch exploitable) ──────────────────────
    events.clear()
    _SCAN_CFG["cves_exploitable"] = (False, False)
    f.run_flow("test-parallel-clean.internal", "", "quick")

    check("clean: interpret NICHT aufgerufen", "interpret" not in _names_called())
    check("clean: threat_intel NICHT aufgerufen", "threat_intel" not in _names_called())
    check("clean: compliance NICHT aufgerufen", "compliance" not in _names_called())
    check("clean: reporting lief trotzdem (skip_teams -> reporting unverändert)",
          "reporting" in _names_called())

finally:
    f._scan_main.run = _orig_scan_run
    f._interpret.run_interpret_flow = _orig_interpret
    f._threatintel.run_threatintel_flow = _orig_threatintel
    f._compliance.run_compliance_flow = _orig_compliance
    f._risk.run_risk_flow = _orig_risk
    f._reporting.run_reporting_flow = _orig_reporting
    if _backup:
        shutil.move(_backup, WORKFLOW_LAST)
    elif os.path.exists(WORKFLOW_LAST):
        os.remove(WORKFLOW_LAST)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
