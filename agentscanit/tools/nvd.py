"""
tools/nvd.py — NVD API v2 client + CrewAI tool wrapper

Queries the National Vulnerability Database for CVE data.
No LLM involved — all data is from the NVD REST API.

Rate limits (without API key): 5 requests per 30 seconds.
Set NVD_API_KEY env var for 50 req/30s.

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import time
import requests
from requests import Session
from typing import Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

NVD_API_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DELAY_NO_KEY  = 6.5   # 5 req / 30s → safe margin between calls
_DELAY_API_KEY = 0.7   # 50 req / 30s

_SESSION: Optional[Session] = None


def _get_session() -> Session:
    """Return a shared requests.Session for NVD API calls (connection reuse)."""
    global _SESSION
    if _SESSION is None:
        _SESSION = Session()
    return _SESSION


def _api_key() -> Optional[str]:
    return os.environ.get("NVD_API_KEY") or None


def _parse_cve(cve_obj: dict) -> dict:
    """Extract structured fields from a raw NVD CVE object."""
    cve_id = cve_obj.get("id", "")

    description = next(
        (d["value"] for d in cve_obj.get("descriptions", []) if d["lang"] == "en"),
        "",
    )

    # CVSS — prefer v3.1 → v3.0 → v2
    metrics = cve_obj.get("metrics", {})
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
            cvss_severity = cd.get("baseSeverity") or entry.get("baseSeverity")
            break

    affected = []
    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected.append(match.get("criteria", ""))

    refs = [r["url"] for r in cve_obj.get("references", [])[:5]]

    return {
        "id":            cve_id,
        "cvss_score":    cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector":   cvss_vector,
        "description":   description,
        "published":     cve_obj.get("published", "")[:10],
        "last_modified": cve_obj.get("lastModified", "")[:10],
        "affected_cpe":  affected[:10],
        "references":    refs,
    }


def _headers() -> dict:
    key = _api_key()
    return {"apiKey": key} if key else {}


def lookup_cve(cve_id: str, api_key: Optional[str] = None) -> dict:
    """Fetch one CVE by ID from NVD API v2.

    On error: {"id": ..., "error": "<reason>"}
    """
    hdrs = {"apiKey": api_key} if api_key else _headers()
    try:
        resp = _get_session().get(
            NVD_API_URL,
            params={"cveId": cve_id.strip()},
            headers=hdrs,
            timeout=15,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
    except requests.HTTPError as e:
        return {"id": cve_id, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        return {"id": cve_id, "error": str(e)}

    if not vulns:
        return {"id": cve_id, "error": "not found in NVD"}
    return _parse_cve(vulns[0]["cve"])


def fetch_cves(cve_ids: list[str], api_key: Optional[str] = None) -> list[dict]:
    """Fetch multiple CVEs with automatic rate limiting."""
    key   = api_key or _api_key()
    delay = _DELAY_API_KEY if key else _DELAY_NO_KEY
    results = []
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(delay)
        results.append(lookup_cve(cve_id, api_key=key))
    return results


def search_nvd(keyword: str, max_results: int = 5) -> list[dict]:
    """Search NVD by keyword (product name + optional version).

    Example: search_nvd("Apache 2.4.51") → list of matching CVE dicts.
    Returns up to max_results entries sorted by CVSS score descending.
    """
    try:
        resp = _get_session().get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": min(max_results, 20)},
            headers=_headers(),
            timeout=20,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
    except requests.HTTPError as e:
        return [{"error": f"HTTP {e.response.status_code}", "keyword": keyword}]
    except Exception as e:
        return [{"error": str(e), "keyword": keyword}]

    results = [_parse_cve(v["cve"]) for v in vulns]
    results.sort(key=lambda r: r.get("cvss_score") or 0, reverse=True)
    return results[:max_results]


# ---------------------------------------------------------------------------
# CrewAI Tool wrapper
# ---------------------------------------------------------------------------

class NvdSearchInput(BaseModel):
    keyword: str = Field(
        description=(
            "Produkt + Version für NVD-Suche, z.B. 'Apache 2.4.51', 'OpenSSH 8.2', "
            "'nginx 1.22'. Immer mit Versionsnummer wenn bekannt."
        )
    )
    max_results: int = Field(default=5, description="Maximale Anzahl CVEs (1-10)")


class NvdSearchTool(BaseTool):
    name: str = "nvd_cve_search"
    description: str = (
        "Sucht CVEs in der National Vulnerability Database (NVD) per Keyword. "
        "Nutze dieses Tool wenn searchsploit keine Ergebnisse liefert oder zur Bestätigung. "
        "Input: Produktname + Version (z.B. 'Apache 2.4.51'). "
        "Gibt CVE-IDs, CVSS-Score, Severity und Beschreibung zurück."
    )
    args_schema: Type[BaseModel] = NvdSearchInput

    def _run(self, keyword: str, max_results: int = 5) -> str:
        import time as _time
        from tools.trace import run_trace
        t0 = _time.time()

        results = search_nvd(keyword, max_results=max_results)

        if not results or "error" in results[0]:
            err = results[0].get("error", "no results") if results else "no results"
            out = f"[NVD] Keine CVEs gefunden für '{keyword}': {err}"
            run_trace.record_execution(["nvd_cve_search", keyword], out, _time.time() - t0)
            return out

        lines = [f"[NVD] CVEs für '{keyword}' ({len(results)} Treffer):"]
        for r in results:
            sev   = r.get("cvss_severity") or "N/A"
            score = r.get("cvss_score") or "N/A"
            desc  = (r.get("description") or "")[:200]
            lines.append(
                f"\n{r['id']} — CVSS {score} ({sev})\n"
                f"  Published: {r.get('published', 'N/A')}\n"
                f"  {desc}"
            )

        out = "\n".join(lines)
        run_trace.record_execution(["nvd_cve_search", keyword], out, _time.time() - t0)
        return out


nvd_tool = NvdSearchTool()
