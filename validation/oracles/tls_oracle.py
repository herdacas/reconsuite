"""validation/oracles/tls_oracle.py — Phase 2: TLS-Konfigurations-Oracle (testssl.sh).

'testssl.sh lokal als Zweitmeinung' (VALIDATION_SPEC.md Phase 2). CLAUDE.md
listet testssl.sh als 'nicht installiert' — das ist inzwischen VERALTET, das
Binary ist real vorhanden (`which testssl` -> /usr/bin/testssl, geprüft
2026-09-12). Nutzt NUR den Protokoll-Check (-p, ~15-30s/Target statt mehrere
Minuten bei vollem Run) — reicht als unabhängige Zweitmeinung zur sslscan-
Bannerzeile, die BUG-25 als Fehlerquelle identifiziert hat.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cache import get, put  # noqa: E402


def fetch(target: str, use_cache: bool = True, timeout: int = 90) -> dict:
    """Live-Protokoll-Check gegen `target`:443. Rückgabe:
    {"status": "OK"|"ERROR"|"TIMEOUT", "protocols": {"TLS1.0": "offered"|"not offered", ...}}
    """
    if use_cache:
        cached = get("tls", target)
        if cached:
            return cached["parsed"]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        json_path = tf.name
    try:
        p = subprocess.run(
            ["testssl", "--quiet", "--color", "0", "-p",
             "--jsonfile-pretty", json_path, target],
            capture_output=True, text=True, timeout=timeout,
        )
        raw_stdout = p.stdout
        with open(json_path) as f:
            findings = json.load(f)
    except subprocess.TimeoutExpired:
        parsed = {"status": "TIMEOUT", "protocols": {}}
        put("tls", target, "testssl -p " + target, raw_response="[TIMEOUT]", parsed=parsed)
        os.unlink(json_path) if os.path.exists(json_path) else None
        return parsed
    except Exception as e:
        parsed = {"status": "ERROR", "error": str(e), "protocols": {}}
        put("tls", target, "testssl -p " + target, raw_response=str(e), parsed=parsed)
        return parsed
    finally:
        if os.path.exists(json_path):
            pass  # unten nach dem Lesen entfernt

    protocols = {}
    proto_ids = {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}
    for entry in findings:
        if isinstance(entry, dict) and entry.get("id") in proto_ids:
            protocols[entry["id"]] = entry.get("finding", "")

    if os.path.exists(json_path):
        os.unlink(json_path)

    parsed = {"status": "OK", "protocols": protocols}
    put("tls", target, "testssl -p " + target, raw_response=raw_stdout[:4000], parsed=parsed)
    return parsed


if __name__ == "__main__":
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "example.com"))
