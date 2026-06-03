#!/usr/bin/env python3
"""
Toolchain-Tester – prüft alle installierten Tools auf Verfügbarkeit.
"""

import subprocess
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from config import (
    PROJECT_DIR, THEHARVESTER_DIR, TESTSSL_DIR, TESTSSL_BIN,
    ENUM4LINUX_BIN, ENUM4LINUX_DIR, EYEWITNESS_BIN, EYEWITNESS_DIR,
    NUCLEI_BIN, AMASS_BIN, ASSETFINDER_BIN, SUBFINDER_BIN,
    SEARCHSPLOIT_BIN, VENV_PYTHON, HTTPX_BIN, GO_BIN,
)

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ---------------------------------------------------------------------------
# Tool-Definitionen
# Jeder Eintrag: cmd zum Versions-/Hilfe-Check, desc, optionales cwd/timeout.
# RC != 0 → WARN (Tool da, aber z.B. --version liefert RC=1).
# FileNotFoundError → FAIL.
# ---------------------------------------------------------------------------

TOOLS = {
    # ── Basis ────────────────────────────────────────────────────────────
    "ping": {
        "cmd": ["ping", "-c", "1", "-W", "1", "127.0.0.1"],
        "desc": "ICMP-Erreichbarkeit",
        "category": "Basis",
    },
    "curl": {
        "cmd": ["curl", "--version"],
        "desc": "HTTP-Requests",
        "category": "Basis",
    },
    "whois": {
        "cmd": ["whois", "--version"],
        "desc": "WHOIS-Abfragen",
        "category": "Basis",
    },
    "dig": {
        "cmd": ["dig", "-v"],
        "desc": "DNS-Abfragen",
        "category": "Basis",
    },

    # ── Active Scanning ──────────────────────────────────────────────────
    "nmap": {
        "cmd": ["nmap", "--version"],
        "desc": "Port-Scanner",
        "category": "Active Scanning",
    },
    "nikto": {
        "cmd": ["nikto", "-Version"],
        "desc": "Web-Schwachstellenscanner",
        "category": "Active Scanning",
    },
    "whatweb": {
        "cmd": ["whatweb", "--version"],
        "desc": "Technologie-Fingerprinting",
        "category": "Active Scanning",
    },
    "gobuster": {
        "cmd": ["gobuster", "version"],
        "desc": "Directory Bruteforce",
        "category": "Active Scanning",
    },
    "ffuf": {
        "cmd": ["ffuf", "-V"],
        "desc": "Web-Fuzzer",
        "category": "Active Scanning",
    },
    "httpx": {
        "cmd": [HTTPX_BIN, "-version"],
        "desc": "HTTP-Probing (ProjectDiscovery)",
        "category": "Active Scanning",
    },
    "naabu": {
        "cmd": ["naabu", "-version"],
        "desc": "Schneller Port-Scanner (ProjectDiscovery)",
        "category": "Active Scanning",
    },
    "nuclei": {
        "cmd": [NUCLEI_BIN, "-version"],
        "desc": "Schwachstellenscanner (Templates)",
        "category": "Active Scanning",
    },

    # ── SSL/TLS ──────────────────────────────────────────────────────────
    "sslscan": {
        "cmd": ["sslscan", "--version"],
        "desc": "SSL/TLS-Scanner",
        "category": "SSL/TLS",
    },
    "testssl.sh": {
        "cmd": [TESTSSL_BIN, "--help"],
        "desc": "Vollständiger TLS-Test (lokal)",
        "category": "SSL/TLS",
        "cwd": TESTSSL_DIR,
    },

    # ── Passive Recon / OSINT ────────────────────────────────────────────
    "sublist3r": {
        "cmd": ["sublist3r", "-h"],
        "desc": "Subdomain-Enumeration (Suchmaschinen)",
        "category": "Passive Recon",
    },
    "subfinder": {
        "cmd": [SUBFINDER_BIN, "-version"],
        "desc": "Subdomain-Enumeration (passiv)",
        "category": "Passive Recon",
    },
    "amass": {
        "cmd": [AMASS_BIN, "-version"],
        "desc": "Subdomain-Enumeration (viele Quellen)",
        "category": "Passive Recon",
        "ok_nonzero": True,
    },
    "assetfinder": {
        "cmd": [ASSETFINDER_BIN, "--help"],
        "desc": "Subdomain/Asset-Finder (crt.sh)",
        "category": "Passive Recon",
        "ok_nonzero": True,
    },
    "dnsx": {
        "cmd": ["dnsx", "-version"],
        "desc": "Massiver DNS-Resolver (ProjectDiscovery)",
        "category": "Passive Recon",
    },
    "dnsrecon": {
        "cmd": ["dnsrecon", "-h"],
        "desc": "DNS-Enumeration",
        "category": "Passive Recon",
        "ok_nonzero": True,
    },
    "katana": {
        "cmd": ["katana", "-version"],
        "desc": "Web-Crawler (ProjectDiscovery)",
        "category": "Passive Recon",
    },
    "waybackurls": {
        "cmd": ["waybackurls", "-h"],
        "desc": "Wayback Machine URL-Sammlung",
        "category": "Passive Recon",
        "ok_nonzero": True,
    },
    "gau": {
        "cmd": ["gau", "--version"],
        "desc": "GetAllUrls – Web-Archive",
        "category": "Passive Recon",
    },
    "searchsploit": {
        "cmd": [SEARCHSPLOIT_BIN, "--help"],
        "desc": "Exploit-DB Suche",
        "category": "Passive Recon",
        "ok_nonzero": True,
    },

    # ── Externe Skripte / Spezial-Tools ──────────────────────────────────
    "theHarvester": {
        "cmd": ["uv", "run", "theHarvester", "-h"],
        "desc": "OSINT (E-Mails, Hosts, Subdomains)",
        "category": "Externe Skripte",
        "cwd": THEHARVESTER_DIR,
        "timeout": 20,
    },
    "enum4linux-ng": {
        "cmd": [VENV_PYTHON, ENUM4LINUX_BIN, "--help"],
        "desc": "SMB/NetBIOS-Enumeration",
        "category": "Externe Skripte",
        "cwd": ENUM4LINUX_DIR,
    },
    "EyeWitness": {
        "cmd": [VENV_PYTHON, EYEWITNESS_BIN, "--help"],
        "desc": "Web-Screenshots",
        "category": "Externe Skripte",
        "cwd": EYEWITNESS_DIR,
        "ok_nonzero": True,
    },
}

# Python-Bibliotheken (via importlib statt subprocess)
PYTHON_LIBS = {
    "ollama":              "Ollama Python Client",
    "crewai":              "CrewAI Framework",
    "duckduckgo_search":   "DuckDuckGo Search",
    "pydantic":            "Pydantic (BaseTool-Schemas)",
    "lancedb":             "LanceDB (Memory-Backend)",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def print_header(text: str):
    print(f"\n{BOLD}{BLUE}{'='*65}{RESET}")
    print(f"{BOLD}{BLUE}{text:^65}{RESET}")
    print(f"{BOLD}{BLUE}{'='*65}{RESET}")


def print_tool(name: str, status: str, message: str = ""):
    if status == "OK":
        icon = f"{GREEN}✅{RESET}"
    elif status == "WARN":
        icon = f"{YELLOW}⚠️ {RESET}"
    else:
        icon = f"{RED}❌{RESET}"
    print(f"  {icon} {name:22} {message}")


def check_tool(name: str, config: dict) -> tuple[str, str]:
    try:
        result = subprocess.run(
            config["cmd"],
            cwd=config.get("cwd"),
            capture_output=True,
            text=True,
            timeout=config.get("timeout", 10),
        )
        if result.returncode == 0:
            return "OK", config.get("desc", "")
        # ok_nonzero=True: Tool läuft, aber --help/--version gibt RC!=0 zurück
        if config.get("ok_nonzero"):
            return "OK", config.get("desc", "")
        return "WARN", f"RC={result.returncode} – {config.get('desc', '')}"
    except FileNotFoundError:
        return "FAIL", "nicht gefunden"
    except subprocess.TimeoutExpired:
        return "WARN", "Timeout (Tool antwortet, aber langsam)"
    except Exception as e:
        return "FAIL", str(e)[:50]


def check_python_lib(lib: str) -> tuple[str, str]:
    # Prüft im venv-Python (wo crewai, ollama etc. installiert sind)
    try:
        result = subprocess.run(
            [VENV_PYTHON, "-c", f"import {lib}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return "OK", ""
        return "FAIL", "pip install erforderlich"
    except Exception:
        return "FAIL", "pip install erforderlich"


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def main():
    print_header("AGENTSCANIT – TOOLCHAIN CHECKER")
    print(f"\n  Projekt: {PROJECT_DIR}")
    print(f"  Python:  {VENV_PYTHON}")
    print(f"  Datum:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {"OK": 0, "WARN": 0, "FAIL": 0}

    # Kategorien geordnet ausgeben
    categories = {}
    for name, cfg in TOOLS.items():
        cat = cfg.get("category", "Sonstige")
        categories.setdefault(cat, []).append((name, cfg))

    for cat, tools in categories.items():
        print(f"\n{BOLD}── {cat} {'─' * (50 - len(cat))}{RESET}")
        for name, cfg in tools:
            status, msg = check_tool(name, cfg)
            results[status] += 1
            print_tool(name, status, msg)

    # Python-Bibliotheken
    print(f"\n{BOLD}── Python-Bibliotheken {'─' * 42}{RESET}")
    for lib, desc in PYTHON_LIBS.items():
        status, msg = check_python_lib(lib)
        results[status] += 1
        display = f"{desc}" if status == "OK" else f"{desc}  → {msg}"
        print_tool(lib, status, display)

    # Zusammenfassung
    print_header("ZUSAMMENFASSUNG")
    total = sum(results.values())
    print(f"\n  {GREEN}✅ Verfügbar:      {results['OK']:>3}{RESET}")
    print(f"  {YELLOW}⚠️  Eingeschränkt:  {results['WARN']:>3}{RESET}")
    print(f"  {RED}❌ Fehlt:          {results['FAIL']:>3}{RESET}")
    print(f"\n  Gesamt: {total} Tools geprüft")

    if results["FAIL"] > 0:
        print(f"\n  {YELLOW}💡 Fehlende System-Tools:{RESET}  apt install <tool> -y")
        print(f"  {YELLOW}💡 Fehlende Go-Tools:{RESET}       go install <tool>@latest")
        print(f"  {YELLOW}💡 Fehlende Python-Libs:{RESET}    pip install <lib>")
    print()


if __name__ == "__main__":
    main()
