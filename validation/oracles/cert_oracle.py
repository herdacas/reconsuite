"""validation/oracles/cert_oracle.py — Phase 2: Zertifikats-Oracle (crt.sh/CT-Logs).

Fragt crt.sh (Certificate-Transparency-Log-Aggregator) ab und vergleicht gegen
die vom Scanner (sslscan-Rawoutput im Trace) gelesene Chain — mind. der
Common-Name/SAN-Abgleich ist ohne Live-TLS-Handshake möglich.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cache import get, put  # noqa: E402


def fetch(target: str, use_cache: bool = True) -> dict:
    """CT-Log-Einträge für `target` von crt.sh. Rückgabe:
    {"status": "OK"|"EMPTY"|"ERROR", "common_names": [...], "n_certs": int}
    """
    if use_cache:
        cached = get("cert", target)
        if cached:
            return cached["parsed"]

    url = f"https://crt.sh/?q={target}&output=json"
    # crt.sh ist ein Community-Service mit dokumentierter Unzuverlässigkeit (502
    # live beobachtet, 2026-09-12) — Retry/Backoff analog agentscanit/tools/nvd.py
    # (BUG-14-Muster: Ausfall SICHTBAR machen statt verschleiern, nicht ewig retryen).
    import time
    raw, last_err = "", None
    for attempt, wait in enumerate((0, 5, 12)):
        if wait:
            time.sleep(wait)
        try:
            p = subprocess.run(["curl", "-s", "-m", "20", url], capture_output=True,
                                text=True, timeout=25)
            raw = p.stdout
            if raw.strip().startswith("[") or raw.strip() == "":
                last_err = None
                break
            last_err = f"non-JSON response (attempt {attempt+1}): {raw[:150]!r}"
        except Exception as e:
            last_err = str(e)
    if last_err is not None:
        parsed = {"status": "ERROR", "error": last_err, "common_names": [], "n_certs": 0}
        put("cert", target, url, raw_response=raw[:2000] or last_err, parsed=parsed)
        return parsed
    try:
        entries = json.loads(raw) if raw.strip() else []
    except Exception as e:
        parsed = {"status": "ERROR", "error": str(e), "common_names": [], "n_certs": 0}
        put("cert", target, url, raw_response=raw[:2000], parsed=parsed)
        return parsed

    if not entries:
        parsed = {"status": "EMPTY", "common_names": [], "n_certs": 0}
    else:
        cns = sorted({e.get("common_name", "") for e in entries if e.get("common_name")})
        parsed = {"status": "OK", "common_names": cns, "n_certs": len(entries)}

    put("cert", target, url, raw_response=raw[:8000], parsed=parsed)
    return parsed


if __name__ == "__main__":
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com"))
