"""AlienVault OTX Threat Intelligence Tool.

Kostenlose API — Account unter https://otx.alienvault.com erforderlich.
API-Key via OTX_API_KEY env-var oder config. Ohne Key: graceful skip.

Endpunkte genutzt:
  CVE:  GET /api/v1/indicators/CVE/<cve>/general
  IPv4: GET /api/v1/indicators/IPv4/<ip>/general
"""

import os
import time
import requests

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_TIMEOUT = 10


def _api_key() -> str:
    return os.environ.get("OTX_API_KEY", "")


def _get(url: str, key: str) -> dict:
    try:
        headers = {"X-OTX-API-KEY": key} if key else {}
        r = requests.get(url, headers=headers, timeout=_TIMEOUT)
        if r.status_code == 401:
            return {"error": "invalid_key"}
        if r.status_code == 404:
            return {"error": "not_found"}
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def lookup_cve(cve_id: str) -> dict:
    """Threat intel for a CVE ID from OTX pulses."""
    key = _api_key()
    if not key:
        return {"id": cve_id, "source": "otx", "status": "no_key"}

    data = _get(f"{_BASE}/CVE/{cve_id}/general", key)
    if "error" in data:
        return {"id": cve_id, "source": "otx", "status": data["error"]}

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    return {
        "id":          cve_id,
        "source":      "otx",
        "status":      "ok",
        "pulse_count": pulse_count,
        "in_the_wild": pulse_count > 0,
    }


def lookup_ip(ip: str) -> dict:
    """Threat intel for an IPv4 address from OTX pulses."""
    key = _api_key()
    if not key:
        return {"ip": ip, "source": "otx", "status": "no_key"}

    data = _get(f"{_BASE}/IPv4/{ip}/general", key)
    if "error" in data:
        return {"ip": ip, "source": "otx", "status": data["error"]}

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    reputation  = data.get("reputation", 0)
    return {
        "ip":          ip,
        "source":      "otx",
        "status":      "ok",
        "pulse_count": pulse_count,
        "reputation":  reputation,
        "malicious":   reputation < 0 or pulse_count > 3,
    }


def bulk_lookup_cves(cve_ids: list[str], delay: float = 0.5) -> list[dict]:
    results = []
    for cve_id in cve_ids:
        results.append(lookup_cve(cve_id))
        if len(cve_ids) > 1:
            time.sleep(delay)
    return results


def bulk_lookup_ips(ips: list[str], delay: float = 0.5) -> list[dict]:
    results = []
    for ip in ips:
        results.append(lookup_ip(ip))
        if len(ips) > 1:
            time.sleep(delay)
    return results
