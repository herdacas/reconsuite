"""Shodan Host Intelligence Tool.

Paid API — Key via SHODAN_API_KEY env-var oder ../api_keys.md. Ohne Key: graceful skip.
Endpunkt: GET https://api.shodan.io/shodan/host/<ip>?key=<API_KEY>
"""

import requests

from ._keys import get_key

_BASE    = "https://api.shodan.io/shodan/host"
_TIMEOUT = 10


def _api_key() -> str:
    return get_key("SHODAN_API_KEY")


def lookup_ip(ip: str) -> dict:
    """Open ports, services, and banners for an IP from Shodan."""
    key = _api_key()
    if not key:
        return {"ip": ip, "source": "shodan", "status": "no_key"}

    try:
        r = requests.get(f"{_BASE}/{ip}", params={"key": key}, timeout=_TIMEOUT)
        if r.status_code == 401:
            return {"ip": ip, "source": "shodan", "status": "invalid_key"}
        if r.status_code == 404:
            return {"ip": ip, "source": "shodan", "status": "not_found"}
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        return {"ip": ip, "source": "shodan", "status": str(e)}

    ports    = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    org      = data.get("org", "")
    vulns    = list(data.get("vulns", {}).keys())

    return {
        "ip":        ip,
        "source":    "shodan",
        "status":    "ok",
        "org":       org,
        "hostnames": hostnames,
        "ports":     ports,
        "vulns":     vulns,       # CVEs Shodan hat direkt erkannt
        "country":   data.get("country_name", ""),
    }


def bulk_lookup_ips(ips: list[str]) -> list[dict]:
    return [lookup_ip(ip) for ip in ips]
