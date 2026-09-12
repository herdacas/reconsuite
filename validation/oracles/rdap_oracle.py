"""validation/oracles/rdap_oracle.py — Phase 2: Registrar/Domaindaten-Oracle (RDAP).

Strukturiertes JSON statt Whois-Freitext (VALIDATION_SPEC.md Phase 2 verlangt
explizit RDAP statt Whois). Nutzt rdap.org als Bootstrap-Proxy (folgt Redirects
zur autoritativen RDAP-Quelle der jeweiligen Registry).
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cache import get, put  # noqa: E402

# Live gefunden (2026-09-12, Validierungsrunde): rdap.org's Bootstrap-Proxy
# unterstützt .de NICHT ("No RDAP service is available for this resource"),
# obwohl DENIC selbst einen funktionierenden RDAP-Endpoint betreibt. 3 von 4
# Apex-Domains in diesem Corpus sind .de -> ohne diesen Fallback wäre der
# RDAP-Oracle für den Großteil des Corpus nutzlos. Kein vollständiges TLD-
# Bootstrap-Replacement (das wäre ein eigenes Projekt) — nur der für DIESEN
# Corpus konkret beobachtete Lückenfall.
_TLD_DIRECT = {"de": "https://rdap.denic.de/domain/{target}"}


def fetch(target: str, use_cache: bool = True) -> dict:
    """RDAP-Lookup für `target`. Rückgabe:
    {"status": "OK"|"NOT_FOUND"|"ERROR", "handle": ..., "statuses": [...], "events": [...]}
    """
    if use_cache:
        cached = get("rdap", target)
        if cached:
            return cached["parsed"]

    tld = target.rsplit(".", 1)[-1].lower()
    urls = [f"https://rdap.org/domain/{target}"]
    if tld in _TLD_DIRECT:
        urls.insert(0, _TLD_DIRECT[tld].format(target=target))

    raw, data = "", {}
    for url in urls:
        try:
            p = subprocess.run(["curl", "-s", "-L", "-m", "15", url], capture_output=True,
                                text=True, timeout=20)
            raw = p.stdout
            data = json.loads(raw) if raw.strip() else {}
        except Exception as e:
            parsed = {"status": "ERROR", "error": str(e)}
            put("rdap", target, url, raw_response=str(e), parsed=parsed)
            return parsed
        if data and "errorCode" not in data:
            break  # Treffer — keine weitere URL probieren

    if not data or "errorCode" in data:
        parsed = {"status": "NOT_FOUND", "raw_error_code": data.get("errorCode")}
    else:
        parsed = {
            "status": "OK",
            "handle": data.get("handle"),
            "ldh_name": data.get("ldhName"),
            "statuses": data.get("status", []),
            "events": [
                {"action": e.get("eventAction"), "date": e.get("eventDate")}
                for e in data.get("events", [])
            ],
        }

    put("rdap", target, url, raw_response=raw[:8000], parsed=parsed)
    return parsed


if __name__ == "__main__":
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com"))
