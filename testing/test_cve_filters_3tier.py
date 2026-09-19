#!/usr/bin/env python3
"""Test für das 3-Stufen-Versions-Gate (2026-09-19, Output-Qualitäts-Fix Punkt 1).

Auslöser: Qualitätsreview des echten pentest-ground.com-full-Scans zeigte, dass
CVE-2023-21839 (Oracle WebLogic, laut externer Recherche die tatsächliche,
absichtlich eingebaute Schwachstelle der Plattform — "ShadowLogic") vom
findings-Task korrekt in cve_references erfasst wurde, im final_report.md aber
KOMPLETT unsichtbar war: das BUG-17-Versions-Gate kennt nur "bestätigt" oder
"versteckt", und WebLogic gibt nie eine Version preis (404 auf Root-Pfad).

User-Vorgabe: eine nicht gefundene CVE ist akzeptabel (False Negative), eine
gefundene aber unterschlagene nicht. Fix: split_by_version_gate() liefert jetzt
4 statt 3 Kategorien — product_confirmed_no_version bleibt SICHTBAR (eigene
Report-Sektion), zählt aber NICHT in Critical/High (verhindert die BUG-20-
Rauschen-Regression, die ursprünglich zum 2-Stufen-Modell führte).

Reproduktion mit ECHTEN Daten dieser Session (kein Synthetik-Fall):
  - scan_body: logs/recon_report_pentest-ground.com_20260919_042517.md (echter Trace)
  - nvd_results: 40 CVE-Dicts, aus logs/interpret_pentest-ground.com_20260919_042938.md
    zurückgeparst (identische Felder wie echte NVD-Lookups: id/cvss_score/severity/
    description/affected_cpe) — das ist Team 2s tatsächlicher, damals produzierter
    Output für genau diesen Scan, keine Fantasie-Daten.
"""
import re
import sys
from pathlib import Path

_SUITE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SUITE_DIR))

import cve_filters  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


def _parse_interpret_md(path: str) -> list[dict]:
    """Parst die echten CVE-Blöcke aus einem interpret_*.md zurück in NVD-Dicts."""
    text = Path(path).read_text(encoding="utf-8")
    parts = re.split(r"(?=### [🔴🟠🟡🟢⚪] CVE-)", text)
    entries = []
    for p in parts:
        m = re.match(r"### [🔴🟠🟡🟢⚪] (CVE-\d{4}-\d+) — CVSS ([\d.]+) \((\w+)\)", p)
        if not m:
            continue
        desc_m = re.search(r"\*\*Description:\*\* (.+?)\n\n", p, re.DOTALL)
        cpes = re.findall(r"- `(cpe:2\.3:[^`]+)`", p)
        entries.append({
            "id": m.group(1),
            "cvss_score": float(m.group(2)),
            "cvss_severity": m.group(3),
            "description": desc_m.group(1).strip() if desc_m else "",
            "affected_cpe": cpes,
            "published": "", "last_modified": "", "cvss_vector": "", "references": [],
        })
    return entries


# --- Reproduktion: echte pentest-ground.com-Daten dieser Session ---
_RECON = str(_SUITE_DIR / "logs" / "recon_report_pentest-ground.com_20260919_042517.md")
_INTERPRET = str(_SUITE_DIR / "logs" / "interpret_pentest-ground.com_20260919_042938.md")

if Path(_RECON).exists() and Path(_INTERPRET).exists():
    scan_body = cve_filters.load_scan_body(_RECON)
    nvd_results = _parse_interpret_md(_INTERPRET)
    check("Reproduktion: 40 CVEs aus dem echten interpret.md zurückgeparst",
          len(nvd_results) == 40)

    version_ok, version_unk_kev, product_confirmed_no_version, fully_dropped = (
        cve_filters.split_by_version_gate(nvd_results, scan_body)
    )

    check("CVE-2023-21839 (WebLogic/ShadowLogic) ist jetzt SICHTBAR in "
          "product_confirmed_no_version (vorher: komplett unterschlagen)",
          any(c["id"] == "CVE-2023-21839" for c in product_confirmed_no_version))

    counted = cve_filters.counted_cves(nvd_results, scan_body)
    crit, high = cve_filters.severity_counts(counted)
    check("CVE-2023-21839 zählt TROTZDEM NICHT in Critical/High (kein BUG-20-Rückfall)",
          not any(c["id"] == "CVE-2023-21839" for c in counted))
    check(f"Regressionscheck: Gelistet/Critical/High unverändert ggü. dem echten "
          f"final_report.md dieser Session (23/3/12, jetzt {len(counted)}/{crit}/{high})",
          (len(counted), crit, high) == (23, 3, 12))

    # CVE-2022-0543 (Redis, die tatsächlich korrekte Plattform-CVE "CipherHeart")
    # muss weiterhin voll versions-bestätigt sein — bestes Ergebnis des Scans, darf
    # durch die neue dritte Stufe nicht beeinträchtigt werden.
    check("CVE-2022-0543 (Redis/CipherHeart) bleibt versions-bestätigt (version_ok)",
          any(c["id"] == "CVE-2022-0543" for c in version_ok))
else:
    print("[SKIP] pentest-ground.com-Session-Dateien nicht gefunden — Reproduktion übersprungen")


# --- Negativkontrolle: Produkt taucht NIRGENDS im Scan-Body auf → bleibt versteckt ---
_fake_scan_body = "nginx 1.31.6 auf Port 80. OpenSSH 8.4p1 auf Port 22."
_unrelated_cve = {
    "id": "CVE-2099-00001", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
    "description": "A vulnerability in TotallyUnrelatedProduct allows RCE.",
    "affected_cpe": ["cpe:2.3:a:acme:totallyunrelatedproduct:1.0:*:*:*:*:*:*:*"],
}
v_ok, v_kev, prod_ok, dropped = cve_filters.split_by_version_gate(
    [_unrelated_cve], _fake_scan_body,
)
check("Negativkontrolle: Produkt ohne jeden Bezug zum Scan-Body bleibt in fully_dropped "
      "(wird NICHT durch die neue Stufe fälschlich sichtbar gemacht)",
      _unrelated_cve in dropped and _unrelated_cve not in prod_ok)

# --- Positivkontrolle: Produkt im Scan-Body, aber ohne Versionsnummer daneben ---
_product_only_body = "Oracle WebLogic admin httpd erkannt auf Port 7001, Version unbekannt."
_weblogic_cve = {
    "id": "CVE-2099-00002", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
    "description": "Vulnerability in the WebLogic Server product of Oracle Fusion Middleware.",
    "affected_cpe": ["cpe:2.3:a:oracle:weblogic_server:14.1.2.0.0:*:*:*:*:*:*:*"],
}
v_ok2, v_kev2, prod_ok2, dropped2 = cve_filters.split_by_version_gate(
    [_weblogic_cve], _product_only_body,
)
check("Positivkontrolle: Produkt im Scan-Body ohne Versionsnummer landet in "
      "product_confirmed_no_version (nicht in version_ok, nicht versteckt)",
      _weblogic_cve in prod_ok2 and _weblogic_cve not in v_ok2 and _weblogic_cve not in dropped2)
check("counted_cves() schließt die versionslose Positivkontroll-CVE weiterhin aus",
      _weblogic_cve not in cve_filters.counted_cves([_weblogic_cve], _product_only_body))

# --- Regressionscheck: version_ok bleibt unverändert, wenn Version genannt ist ---
_versioned_body = "OpenSSH 8.4p1 Debian 5+deb11u7 erkannt auf Port 4445."
_ssh_cve = {
    "id": "CVE-2099-00003", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
    "description": "Vulnerability in OpenSSH allows RCE.",
    "affected_cpe": ["cpe:2.3:a:openbsd:openssh:8.4:*:*:*:*:*:*:*"],
}
v_ok3, _, _, _ = cve_filters.split_by_version_gate([_ssh_cve], _versioned_body)
check("Regressionscheck: versions-bestätigte CVE landet weiterhin in version_ok",
      _ssh_cve in v_ok3)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
