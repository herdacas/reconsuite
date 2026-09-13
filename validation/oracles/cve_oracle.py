"""validation/oracles/cve_oracle.py — Phase 2: CVE/Schwachstellen-Oracle (NVD).

Eigenständige, leichte NVD-Query-Funktion (KEIN Import von agentscanit/tools/nvd.py
— das zieht crewai.tools.BaseTool als Modul-Level-Import, unnötige Kopplung für
diese reine Validierungs-Query). CVE-IDs müssen gegen die NVD-API auflösbar sein,
sonst FABRICATED (VALIDATION_SPEC.md Phase 2). Kein NVD_API_KEY im Projekt
konfiguriert -> Rate-Limit 5 req/30s wird respektiert (time.sleep zwischen Calls).
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cache import get, put  # noqa: E402

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DELAY_S = 6.5  # 5 req/30s ohne API-Key, siehe agentscanit/tools/nvd.py-Kommentar
_last_call_ts = [0.0]


def _rate_limit():
    elapsed = time.time() - _last_call_ts[0]
    if elapsed < _DELAY_S:
        time.sleep(_DELAY_S - elapsed)
    _last_call_ts[0] = time.time()


def fetch(cve_id: str, use_cache: bool = True) -> dict:
    """Prüft ob `cve_id` in der NVD existiert. Rückgabe:
    {"status": "EXISTS"|"FABRICATED"|"ERROR", "cvss": float|None,
     "severity": str|None, "affected_cpe": [...], "description": str}
    """
    cve_id = cve_id.strip().upper()
    if use_cache:
        cached = get("cve", cve_id, max_age_s=7 * 86400)  # CVE-Daten ändern sich selten
        if cached:
            return cached["parsed"]

    _rate_limit()
    url = f"{_NVD_URL}?cveId={cve_id}"
    try:
        p = subprocess.run(["curl", "-s", "-m", "20", url], capture_output=True,
                            text=True, timeout=25)
        raw = p.stdout
        data = json.loads(raw) if raw.strip() else {}
    except Exception as e:
        parsed = {"status": "ERROR", "error": str(e)}
        put("cve", cve_id, url, raw_response=str(e), parsed=parsed)
        return parsed

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        parsed = {"status": "FABRICATED", "cvss": None, "severity": None,
                   "affected_cpe": [], "description": ""}
        put("cve", cve_id, url, raw_response=raw[:4000], parsed=parsed)
        return parsed

    cve = vulns[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss, severity = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss = m.get("cvssData", {}).get("baseScore")
            severity = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
            break

    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    affected.append(m.get("criteria", ""))

    parsed = {
        "status": "EXISTS", "cvss": cvss, "severity": severity,
        "affected_cpe": affected[:20], "description": desc[:500],
    }
    put("cve", cve_id, url, raw_response=raw[:8000], parsed=parsed)
    return parsed


if __name__ == "__main__":
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-6387"))
