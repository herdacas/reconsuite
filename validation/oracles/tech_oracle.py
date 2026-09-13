"""validation/oracles/tech_oracle.py — Phase 2: Tech-Fingerprinting-Oracle.

EHRLICHE EINSCHRÄNKUNG (gehört in Phase 6 "Grenzen der Aussage"): Dies ist KEIN
vollständig unabhängiger zweiter Fingerprinter-TOOL-Lauf (das würde ein zweites
externes Fingerprinting-Tool/eine externe API mit eigenem Netzwerk-Request
brauchen, die in dieser Umgebung nicht verfügbar/autorisiert ist). Stattdessen:
ein deterministischer, regelbasierter Parser der VOM LLM UNABHÄNGIG dieselben
bereits im Fixture-Trace vorhandenen HTTP-Header (Server/X-Powered-By/etc.)
re-interpretiert — schwächer als ein echter Zweit-Scan, aber strikt unabhängig
von der LLM-Interpretation, die validiert werden soll (keine Zirkularität).
"""
import re

_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"apache", re.I), "Apache httpd"),
    (re.compile(r"microsoft-iis", re.I), "Microsoft IIS"),
    (re.compile(r"litespeed", re.I), "LiteSpeed"),
    (re.compile(r"varnish", re.I), "Varnish"),
    (re.compile(r"php", re.I), "PHP"),
    (re.compile(r"express", re.I), "Express (Node.js)"),
    (re.compile(r"asp\.net", re.I), "ASP.NET"),
    (re.compile(r"wordpress|wp-", re.I), "WordPress"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"typo3", re.I), "TYPO3"),
    (re.compile(r"openssh", re.I), "OpenSSH"),
]

_HEADER_KEYS = ("server", "x-powered-by", "via", "x-generator")


def fetch_from_raw_outputs(raw_outputs: list[str]) -> dict:
    """Extrahiert Tech-Labels deterministisch aus bereits vorhandenen HTTP-
    Rohantworten (KEIN neuer Netzwerk-Call — arbeitet auf denselben Daten wie
    der zu prüfende Scanner, siehe Docstring-Einschränkung oben).
    """
    labels: set[str] = set()
    haystack = "\n".join(raw_outputs)
    for pattern, label in _RULES:
        if pattern.search(haystack):
            labels.add(label)
    return {"status": "OK", "labels": sorted(labels), "method": "header_regex_independent_of_llm"}


if __name__ == "__main__":
    import sys
    text = sys.stdin.read() if not sys.stdin.isatty() else "Server: nginx\nX-Powered-By: PHP/8.2"
    print(fetch_from_raw_outputs([text]))
