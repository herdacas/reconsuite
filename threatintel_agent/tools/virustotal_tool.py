"""VirusTotal Reputation Tool.

Paid API (free tier: 500 req/day) — Key via VT_API_KEY env-var.
Ohne Key: graceful skip.

Endpunkte genutzt:
  IP:  GET https://www.virustotal.com/api/v3/ip_addresses/<ip>
  CVE: GET https://www.virustotal.com/api/v3/vulnerabilities/<cve>
"""

import os
import requests

_BASE    = "https://www.virustotal.com/api/v3"
_TIMEOUT = 10


def _api_key() -> str:
    return os.environ.get("VT_API_KEY", "")


def _get(path: str, key: str) -> dict:
    try:
        r = requests.get(
            f"{_BASE}/{path}",
            headers={"x-apikey": key},
            timeout=_TIMEOUT,
        )
        if r.status_code == 401:
            return {"error": "invalid_key"}
        if r.status_code == 404:
            return {"error": "not_found"}
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def lookup_ip(ip: str) -> dict:
    """Malicious/suspicious vote count for an IP from VT community."""
    key = _api_key()
    if not key:
        return {"ip": ip, "source": "virustotal", "status": "no_key"}

    data = _get(f"ip_addresses/{ip}", key)
    if "error" in data:
        return {"ip": ip, "source": "virustotal", "status": data["error"]}

    attrs     = data.get("data", {}).get("attributes", {})
    stats     = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return {
        "ip":         ip,
        "source":     "virustotal",
        "status":     "ok",
        "malicious":  malicious,
        "suspicious": suspicious,
        "flagged":    malicious > 0 or suspicious > 2,
        "country":    attrs.get("country", ""),
        "asn":        attrs.get("asn", ""),
        "as_owner":   attrs.get("as_owner", ""),
    }


def lookup_cve(cve_id: str) -> dict:
    """CVE details and exploit availability from VT."""
    key = _api_key()
    if not key:
        return {"id": cve_id, "source": "virustotal", "status": "no_key"}

    data = _get(f"vulnerabilities/{cve_id}", key)
    if "error" in data:
        return {"id": cve_id, "source": "virustotal", "status": data["error"]}

    attrs      = data.get("data", {}).get("attributes", {})
    exploit    = attrs.get("exploit_urls", [])
    cvss3      = attrs.get("cvss_score", None)

    return {
        "id":            cve_id,
        "source":        "virustotal",
        "status":        "ok",
        "cvss3":         cvss3,
        "exploit_urls":  exploit[:3],
        "has_exploit":   len(exploit) > 0,
    }


def bulk_lookup_ips(ips: list[str]) -> list[dict]:
    return [lookup_ip(ip) for ip in ips]


def bulk_lookup_cves(cve_ids: list[str]) -> list[dict]:
    return [lookup_cve(cve_id) for cve_id in cve_ids]
