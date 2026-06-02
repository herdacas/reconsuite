"""
tools/nvd.py — NVD API v2 client

Queries the National Vulnerability Database for CVE data.
No LLM involved — all data is from the NVD REST API.

Rate limits (without API key): 5 requests per 30 seconds.
Set NVD_API_KEY env var for 50 req/30s.

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import time
import requests
from typing import Optional

NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DELAY_NO_KEY = 6.5   # 5 req / 30s → safe margin between calls
_DELAY_API_KEY = 0.7  # 50 req / 30s


def _api_key() -> Optional[str]:
    return os.environ.get("NVD_API_KEY") or None


def lookup_cve(cve_id: str, api_key: Optional[str] = None) -> dict:
    """Fetch one CVE from NVD API v2. Returns a structured dict.

    Keys in result:
        id, cvss_score, cvss_severity, cvss_vector,
        description, published, last_modified,
        affected_cpe (list), references (list)

    On error: {"id": ..., "error": "<reason>"}
    """
    headers = {}
    key = api_key or _api_key()
    if key:
        headers["apiKey"] = key

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id.strip()},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.HTTPError as e:
        return {"id": cve_id, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"id": cve_id, "error": str(e)}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"id": cve_id, "error": "not found in NVD"}

    cve = vulns[0]["cve"]

    # English description
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "",
    )

    # CVSS — prefer v3.1 → v3.0 → v2
    # Note: v3.x stores baseSeverity inside cvssData; v2 stores it on the metric object.
    metrics = cve.get("metrics", {})
    cvss_score    = None
    cvss_severity = None
    cvss_vector   = None
    for key_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key_name, [])
        if entries:
            entry = entries[0]
            cd = entry.get("cvssData", {})
            cvss_score    = cd.get("baseScore")
            cvss_vector   = cd.get("vectorString")
            # v3.x: severity in cvssData; v2: severity on metric object directly
            cvss_severity = cd.get("baseSeverity") or entry.get("baseSeverity")
            break

    # Affected CPE strings (vulnerable=True entries only)
    affected = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected.append(match.get("criteria", ""))

    refs = [r["url"] for r in cve.get("references", [])[:5]]

    return {
        "id":            cve_id,
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector":   cvss_vector,
        "description":   description,
        "published":     cve.get("published", "")[:10],
        "last_modified": cve.get("lastModified", "")[:10],
        "affected_cpe":  affected[:10],
        "references":    refs,
    }


def fetch_cves(cve_ids: list[str], api_key: Optional[str] = None) -> list[dict]:
    """Fetch multiple CVEs with automatic rate limiting.

    Respects NVD rate limits: 6.5s between calls without key, 0.7s with key.
    """
    key   = api_key or _api_key()
    delay = _DELAY_API_KEY if key else _DELAY_NO_KEY

    results = []
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(delay)
        results.append(lookup_cve(cve_id, api_key=key))
    return results
