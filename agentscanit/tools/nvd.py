"""
tools/nvd.py — NVD API v2 client + CrewAI tool wrapper

Queries the National Vulnerability Database for CVE data.
No LLM involved — all data is from the NVD REST API.

Rate limits (without API key): 5 requests per 30 seconds.
Set NVD_API_KEY env var for 50 req/30s.

API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import asyncio
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


# NVD is frequently slow/overloaded (503 + multi-second latency). A single
# 15-20s timeout produced empty CVE results, which then forced findings onto a
# versionless searchsploit keyword fallback (BUG-14). Retry transient failures
# (503/502/504/429 + read timeouts) with backoff before giving up.
_NVD_TIMEOUT       = 30
_NVD_MAX_RETRIES   = 3
_NVD_RETRY_STATUS  = {502, 503, 504, 429}


def _nvd_get(params: dict, *, timeout: int = _NVD_TIMEOUT,
             api_key: Optional[str] = None) -> requests.Response:
    """GET against the NVD API with retry/backoff on transient failures.

    Raises the last exception (or HTTPError) if all attempts fail, so callers
    keep their existing requests.HTTPError / Exception handling.
    """
    hdrs = {"apiKey": api_key} if api_key else _headers()
    last_exc: Optional[Exception] = None
    for attempt in range(_NVD_MAX_RETRIES):
        try:
            resp = _get_session().get(
                NVD_API_URL, params=params, headers=hdrs, timeout=timeout,
            )
            if resp.status_code in _NVD_RETRY_STATUS and attempt < _NVD_MAX_RETRIES - 1:
                time.sleep(min(4 * (attempt + 1), 12))
                continue
            return resp
        except (requests.Timeout, requests.ConnectionError) as e:
            last_exc = e
            if attempt < _NVD_MAX_RETRIES - 1:
                time.sleep(min(4 * (attempt + 1), 12))
                continue
            raise
    # Exhausted retries on retryable status codes — return the last response so
    # raise_for_status() surfaces the real HTTP error to the caller.
    if last_exc is not None:
        raise last_exc
    return resp


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
    try:
        resp = _nvd_get({"cveId": cve_id.strip()}, api_key=api_key)
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


def cpe_search_nvd(vendor: str, product: str, version: str = "", max_results: int = 5) -> list[dict]:
    """Search NVD CVEs via CPE virtualMatchString (precise, version-aware).

    Unlike keyword search (which returns pubDate:asc → oldest first), this function:
    1. Fetches totalResults to know the list size
    2. Pages to the END of the pubDate:asc list (= newest CVEs)
    3. Sorts locally by CVSS score descending

    For Oracle WebLogic (309 CVEs): returns CVE-2025-21535 (CVSS 9.8) instead of
    CVE-2008-3257 (CVSS 10.0, from 2008) that keyword search returns.
    """
    cpe_string = f"cpe:2.3:a:{vendor}:{product}"
    if version:
        cpe_string += f":{version}:*:*:*:*:*:*:*"

    delay = _DELAY_API_KEY if _api_key() else _DELAY_NO_KEY

    try:
        # Step 1: get total count
        r1 = _nvd_get({"virtualMatchString": cpe_string, "resultsPerPage": 1})
        r1.raise_for_status()
        total = r1.json().get("totalResults", 0)
        if total == 0:
            return [{"error": f"No CVEs for CPE {cpe_string}", "cpe": cpe_string}]

        time.sleep(delay)

        # Step 2: fetch newest 100 (last page of pubDate:asc = most recent).
        # Pool of 100 ensures CVSS-7.5 CVEs survive the sort even when 6+ CVSS-9.8
        # entries are present (e.g. Oracle WebLogic has 10+ CVSS-9.8 in recent years).
        fetch_count = min(100, total)
        start_index = max(0, total - fetch_count)
        r2 = _nvd_get({
            "virtualMatchString": cpe_string,
            "resultsPerPage": fetch_count,
            "startIndex": start_index,
        })
        r2.raise_for_status()
        vulns = r2.json().get("vulnerabilities", [])

    except requests.HTTPError as e:
        return [{"error": f"HTTP {e.response.status_code}", "cpe": cpe_string}]
    except Exception as e:
        return [{"error": str(e), "cpe": cpe_string}]

    results = [_parse_cve(v["cve"]) for v in vulns]

    try:
        from agentscanit.tools.cpe_map import NOTABLE_CVES
    except ImportError:
        from tools.cpe_map import NOTABLE_CVES  # fallback when run from agentscanit/
    notable_ids = NOTABLE_CVES.get((vendor, product), [])

    # Fetch any notable CVEs missing from the pool entirely
    pool_ids = {r["id"] for r in results}
    for cve_id in notable_ids:
        if cve_id not in pool_ids:
            time.sleep(delay)
            extra = lookup_cve(cve_id)
            if "error" not in extra:
                results.append(extra)
                pool_ids.add(cve_id)

    results.sort(key=lambda r: r.get("cvss_score") or 0, reverse=True)
    cap = min(max_results, 20)
    top = results[:cap]

    # Guarantee notable CVEs appear in the output even if crowded out by CVSS sort.
    # They are appended after the sorted slice — agent sees both high-CVSS and pinned entries.
    top_ids = {r["id"] for r in top}
    for cve_id in notable_ids:
        if cve_id not in top_ids:
            for r in results:
                if r["id"] == cve_id:
                    top.append(r)
                    break
    return top


def search_nvd(keyword: str, max_results: int = 5) -> list[dict]:
    """Search NVD by keyword (product name + optional version).

    Example: search_nvd("Apache 2.4.51") → list of matching CVE dicts.
    Returns up to max_results entries sorted by CVSS score descending.
    Fetches a larger pool (max_results * 4, min 40) so that the local
    CVSS sort has enough candidates — NVD API v2 always returns results
    sorted by pubDate:asc (oldest first, no server-side sort parameter).
    """
    fetch_count = min(max(max_results * 4, 40), 50)
    try:
        resp = _nvd_get({"keywordSearch": keyword, "resultsPerPage": fetch_count})
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

    async def _arun(self, keyword: str, max_results: int = 5) -> str:
        import time as _time
        from tools.trace import run_trace
        t0 = _time.time()

        # Run blocking HTTP call in thread pool — non-blocking for async callers
        results = await asyncio.to_thread(search_nvd, keyword, max_results)

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


# ---------------------------------------------------------------------------
# CPE-based CVE lookup tool (Phase 9 — replaces keyword guessing)
# ---------------------------------------------------------------------------

class NvdCpeInput(BaseModel):
    banner: str = Field(
        description=(
            "Service-Banner oder -Name aus dem Scan-Output, z.B. 'Oracle WebLogic 12.2.1', "
            "'nginx/1.22.1', 'OpenSSH 8.2p1', 'Apache Tomcat 9.0.65'. "
            "Wird deterministisch auf CPE vendor:product gemappt — kein Keyword-Rauschen."
        )
    )
    version: str = Field(
        default="",
        description="Versionsnummer wenn bekannt, z.B. '8.2', '12.2.1.0'. Leer lassen wenn unbekannt.",
    )
    max_results: int = Field(default=10, description="Maximale Anzahl CVEs (1-20)")


class NvdCpeTool(BaseTool):
    name: str = "nvd_cpe_lookup"
    description: str = (
        "Präzises CVE-Lookup via NVD CPE-API — deterministisches Banner→CPE-Mapping, "
        "keine Keyword-Streuung. Liefert die neuesten und schwerwiegendsten CVEs für "
        "ein Produkt (CVSS-sortiert, neuste zuerst). "
        "Nutze dieses Tool VOR nvd_cve_search wenn du den Service-Banner kennst. "
        "Beispiele: banner='Oracle WebLogic 12.2.1' → CVE-2023-21839, CVE-2025-21535. "
        "banner='OpenSSH 8.2p1' → CVE-2023-38408. "
        "banner='nginx 1.22.1' → aktuelle nginx CVEs."
    )
    args_schema: Type[BaseModel] = NvdCpeInput

    def _run(self, banner: str, version: str = "", max_results: int = 10) -> str:
        import time as _time
        from tools.trace import run_trace
        from tools.cpe_map import banner_to_cpe
        t0 = _time.time()

        mapping = banner_to_cpe(banner)
        if not mapping:
            out = (
                f"[NVD-CPE] Kein CPE-Mapping für '{banner}'. "
                f"Fallback: nvd_cve_search verwenden."
            )
            run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
            return out

        vendor, product = mapping
        results = cpe_search_nvd(vendor, product, version=version, max_results=max_results)

        if not results or "error" in results[0]:
            err = results[0].get("error", "no results") if results else "no results"
            out = f"[NVD-CPE] Keine CVEs für {vendor}:{product}: {err}"
            run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
            return out

        cpe_str = f"cpe:2.3:a:{vendor}:{product}"
        if version:
            cpe_str += f":{version}"
        lines = [f"[NVD-CPE] CVEs für {cpe_str} ({len(results)} Top-Treffer nach CVSS):"]
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
        run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
        return out

    async def _arun(self, banner: str, version: str = "", max_results: int = 10) -> str:
        import time as _time
        from tools.trace import run_trace
        from tools.cpe_map import banner_to_cpe
        t0 = _time.time()

        mapping = banner_to_cpe(banner)
        if not mapping:
            out = (
                f"[NVD-CPE] Kein CPE-Mapping für '{banner}'. "
                f"Fallback: nvd_cve_search verwenden."
            )
            run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
            return out

        vendor, product = mapping
        results = await asyncio.to_thread(cpe_search_nvd, vendor, product, version, max_results)

        if not results or "error" in results[0]:
            err = results[0].get("error", "no results") if results else "no results"
            out = f"[NVD-CPE] Keine CVEs für {vendor}:{product}: {err}"
            run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
            return out

        cpe_str = f"cpe:2.3:a:{vendor}:{product}"
        if version:
            cpe_str += f":{version}"
        lines = [f"[NVD-CPE] CVEs für {cpe_str} ({len(results)} Top-Treffer nach CVSS):"]
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
        run_trace.record_execution(["nvd_cpe_lookup", banner], out, _time.time() - t0)
        return out


nvd_cpe_tool = NvdCpeTool()
