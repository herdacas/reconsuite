#!/usr/bin/env python3
"""Test für das gebündelte CVE-Rendering in threatintel_flow.py (2026-09-19,
Output-Qualitäts-Fix Punkt 4).

Live gefunden (pentest-ground.com-Scan, Output-Qualitäts-Review):
threatintel_pentest-ground.com_*.md zeigte 40 "### CVE-X"-Abschnitte, darunter
JEWEILS keinerlei Detailzeile (kein OTX-Pulse-Count, kein VT-Exploit-Count,
nicht mal "kein API-Key konfiguriert") — reines Rauschen. Zusätzlicher, davor
unentdeckter Bug: der alte if/elif-Zweig hatte KEIN else für einen echten
API-Fehlerstring (data["error"]) — der wurde komplett verschluckt statt
angezeigt.

Fix: CVEs mit echten OTX/VT-Nutzdaten bekommen weiterhin einen vollen
Abschnitt; alle anderen werden nach ihrem (jetzt sichtbaren) Status gruppiert
in Sammelzeilen zusammengefasst statt 1:1 als leere Abschnitte gerendert.
Reines Rendering — kein LLM/Logik betroffen (Team 4 ist deterministisch).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import threatintel_agent.threatintel_flow as tif  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


def _run_write_report(cve_ids, otx_cve_data, vt_cve_data):
    flow = tif.ThreatIntelFlow()
    flow.state.scan_target = "test-target.internal"
    flow.state.cve_ids = cve_ids
    flow.state.ips = []
    flow.state.otx_cve_data = otx_cve_data
    flow.state.vt_cve_data = vt_cve_data
    flow.write_report()
    with open(flow.state.report_path, encoding="utf-8") as f:
        content = f.read()
    import os
    os.remove(flow.state.report_path)
    return content


# --- Reproduktion: 40 CVEs, alle ohne jede Nutzdaten (wie real beobachtet) ---
_real_cves = ["CVE-2023-38408", "CVE-2026-60002", "CVE-2022-0543", "CVE-2023-21839",
              "CVE-2020-14882"]  # kleinerer Ausschnitt reicht für den Reproduktionsbeweis
otx_no_data = [{"id": c, "source": "otx", "status": "not found"} for c in _real_cves]
vt_no_data  = [{"id": c, "source": "virustotal", "status": "not found"} for c in _real_cves]
content = _run_write_report(_real_cves, otx_no_data, vt_no_data)

check("Reproduktion: KEINE 5 leeren '### CVE-X'-Abschnitte mehr im Output",
      content.count("### ⚪") == 0 and content.count("### 🔴") == 0)
check("Reproduktion: EINE gebündelte Sammelzeile statt 5 leerer Abschnitte",
      "5/5 CVE(s) ohne Threat-Intel-Treffer" in content)
check("Reproduktion: der zuvor verschluckte Fehlerstatus ('not found') ist jetzt sichtbar",
      "not found" in content)
check("Reproduktion: alle 5 CVE-IDs sind trotzdem namentlich in der Sammelzeile aufgeführt "
      "(kein Informationsverlust)",
      all(c in content for c in _real_cves))

# --- Regressionscheck: eine CVE MIT echten Daten bekommt weiterhin ihren vollen Abschnitt ---
otx_mixed = [
    {"id": "CVE-2022-0543", "source": "otx", "status": "ok", "pulse_count": 3, "in_the_wild": True},
    {"id": "CVE-2023-38408", "source": "otx", "status": "not found"},
]
vt_mixed = [{"id": "CVE-2023-38408", "source": "virustotal", "status": "no_key"}]
content2 = _run_write_report(["CVE-2022-0543", "CVE-2023-38408"], otx_mixed, vt_mixed)

check("Regressionscheck: CVE MIT echten OTX-Daten bekommt weiterhin vollen '### 🔴'-Abschnitt",
      "### 🔴 CVE-2022-0543" in content2 and "OTX Pulses:** 3" in content2)
check("Regressionscheck: CVE OHNE Daten landet in der Sammelzeile, nicht als leerer Abschnitt",
      "### ⚪ CVE-2023-38408" not in content2 and "CVE-2023-38408" in content2)
check("Regressionscheck: 'no_key'-Status ist in der Sammelzeile sichtbar (VT)",
      "no_key" in content2)

# --- Negativkontrolle: keine CVEs -> keine CVE-Sektion überhaupt ---
content3 = _run_write_report([], [], [])
check("Negativkontrolle: keine CVE-IDs -> '## CVE Threat Intelligence' fehlt komplett",
      "## CVE Threat Intelligence" not in content3)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
