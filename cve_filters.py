"""
recon-suite/cve_filters.py — Shared CVE version-gate filtering (BUG-17 / BUG-22-Nachfolge)

Single Source of Truth für "welche NVD-CVEs zählen als bestätigtes Finding".
Ursprünglich nur in reporting/reporting_flow.py implementiert; risk_scorer/risk_flow.py
zählte Critical/High direkt aus dem ungefilterten nvd_results → zwei Teams, zwei
unterschiedliche Zahlen für denselben Scan (Backlog-Eintrag 2026-09-11, CLAUDE.md).

Beide Teams importieren jetzt dieselben Funktionen, damit "Critical: N" garantiert
identisch ist, egal ob im Final Report (Team 3) oder im Risk Score (Team 6).

Kein LLM, keine Seiteneffekte — reine Textanalyse/Filterung.
"""

import re

# Produkt-Aliasse: NVD-CPE-Produktname → Banner-Schreibweise(n) des Scanners.
# NVD nennt es "http_server", nmap-Banner sagt "httpd"/"apache httpd".
_ALIAS = {
    "http server": ["httpd"],
    "weblogic server": ["weblogic"],
}
# Generische Tokens die als alleiniges Keyword zu breit matchen würden.
_TOO_GENERIC = {"server", "http", "https", "service", "manager", "core", "web",
                "linux", "enterprise", "framework"}

_KEV_PHRASES = ("exploited in the wild", "known to be exploited", "actively exploited")


def cve_product_keywords(cve: dict) -> set[str]:
    """Produkt-Keywords einer CVE aus den affected_cpe-Einträgen extrahieren.

    cpe:2.3:a:openbsd:openssh:* → {'openssh'}, apache:tomcat → {'tomcat'}.
    Genutzt um zu prüfen ob der Scan für dieses Produkt eine Version erkannt hat.
    """
    kws: set[str] = set()
    for cpe in cve.get("affected_cpe", []) or []:
        parts = cpe.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
        if len(parts) >= 5:
            product = parts[4].replace("_", " ").strip().lower()
            if not product or product == "*":
                continue
            kws.add(product)                        # volles Produkt, z.B. "weblogic server"
            kws.update(_ALIAS.get(product, []))     # Banner-Aliasse, z.B. "httpd"
            last = product.split()[-1]
            if last not in _TOO_GENERIC:            # last-token nur wenn spezifisch
                kws.add(last)                       # z.B. "tomcat", "openssh"
    return kws


def version_confirmed_in_scan(cve: dict, scan_body: str) -> bool:
    """True wenn der Scan für das CVE-Produkt eine konkrete Version erkannt hat.

    Banner-Versions-Gate (BUG-17): Eine CVE ist nur dann versions-verifizierbar wenn
    im Scan-Body das Produkt-Keyword von einer Versionsnummer (\\d+\\.\\d+) gefolgt
    wird (z.B. "OpenSSH 6.6.1p1"). Bei versionslosem Banner ("Apache Tomcat version
    unknown") bleibt der Versions-Match unbestätigt → potenzielles False-Positive.
    """
    if not scan_body:
        return False
    body = scan_body.lower()
    for kw in cve_product_keywords(cve):
        if len(kw) < 3:
            continue
        # Produkt-Keyword gefolgt (innerhalb ~20 Zeichen) von einer Versionsnummer
        pattern = re.escape(kw) + r"[^\n]{0,20}?\d+\.\d+"
        if re.search(pattern, body):
            return True
    return False


def is_kev(cve: dict) -> bool:
    """CISA-KEV-Heuristik: NVD-Beschreibung nennt aktive Ausnutzung."""
    desc = (cve.get("description") or "").lower()
    return any(phrase in desc for phrase in _KEV_PHRASES)


def valid_nvd_results(nvd_results: list[dict]) -> list[dict]:
    """NVD-Ergebnisse ohne Fehler (echte, bestätigte CVE-Datensätze)."""
    return [r for r in nvd_results if "error" not in r]


def split_by_version_gate(
    valid_results: list[dict], scan_body: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Teilt valide NVD-CVEs in (version_ok, version_unk_kev, version_unk_dropped).

    version_ok           — Produktversion im Scan erkannt, passt zur CVE.
    version_unk_kev       — keine Versions-Bestätigung, aber aktiv ausgenutzt (KEV-Ausnahme).
    version_unk_dropped   — keine Versions-Bestätigung, kein KEV → nicht verwertbar.
    """
    version_ok = [r for r in valid_results if version_confirmed_in_scan(r, scan_body)]
    version_unk = [r for r in valid_results if r not in version_ok]
    version_unk_kev = [r for r in version_unk if is_kev(r)]
    version_unk_dropped = [r for r in version_unk if not is_kev(r)]
    return version_ok, version_unk_kev, version_unk_dropped


def counted_cves(nvd_results: list[dict], scan_body: str) -> list[dict]:
    """CVEs, die in Kopfzeilen-/Score-Zählungen einfließen dürfen: version-verifiziert
    + KEV-Ausnahmen. Versionslose, nicht aktiv ausgenutzte CVEs zählen NICHT (BUG-20)."""
    valid = valid_nvd_results(nvd_results)
    version_ok, version_unk_kev, _ = split_by_version_gate(valid, scan_body)
    return version_ok + version_unk_kev


def severity_counts(cves: list[dict]) -> tuple[int, int]:
    """(critical_count, high_count) aus einer Liste NVD-CVE-Dicts (Feld cvss_severity)."""
    crit = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "CRITICAL")
    high = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "HIGH")
    return crit, high


def load_scan_body(scan_report_path: str) -> str:
    """Lädt den Scan-Report-Body (recon_report_*.md) für die Versions-Gate-Suche.

    Schneidet alles vor der ersten Markdown-Überschrift ab und entfernt die
    '## CVE References'-Sektion (dieselbe Extraktion wie reporting_flow.merge()).
    Gibt "" zurück wenn der Pfad fehlt/nicht lesbar ist — Aufrufer behandeln das
    wie "keine Version bestätigt" (fail-safe: eher zu wenig als zu viel zählen).
    """
    if not scan_report_path:
        return ""
    try:
        with open(scan_report_path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return ""
    match = re.search(r'^(#.+)', raw, re.MULTILINE)
    if match:
        raw = raw[match.start():]
    raw = re.split(r'\n## CVE References', raw)[0].rstrip()
    return raw
