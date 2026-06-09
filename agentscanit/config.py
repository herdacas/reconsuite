"""
config.py – Zentrale Konfiguration für AgentScanIT
Alle Konstanten an einem Ort. Kein Hardcoding in den Modulen.

Modell- und API-Einstellungen werden aus models.json geladen (lokal, gitignored).
Fehlt models.json, gelten die Defaults unten.
"""

import json
import os

# ─── models.json einlesen (lokal, gitignored) ─────────────────────────────────

_MODELS_FILE = os.path.join(os.path.dirname(__file__), "models.json")
_models_cfg: dict = {}

if os.path.exists(_MODELS_FILE):
    try:
        with open(_MODELS_FILE, "r", encoding="utf-8") as _f:
            _models_cfg = json.load(_f)
    except Exception as _e:
        print(f"[config] Warning: could not read models.json: {_e}")

def _m(key: str, default: str) -> str:
    """Liest einen Wert aus models.json oder gibt den Default zurück."""
    return _models_cfg.get("models", {}).get(key, default)

def _ml(key: str, default: str) -> str:
    """Liest einen Wert aus der local_fallback_models-Sektion oder gibt den Default zurück."""
    return _models_cfg.get("local_fallback_models", {}).get(key, default)

# ─── LLM ──────────────────────────────────────────────────────────────────────

MODEL_ANALYSIS  = _m("analysis", "qwen3-coder:30b")
MODEL_CODE      = _m("code",     "qwen3-coder:30b")
MODEL_RESEARCH  = _m("research", "qwen3-coder:30b")
EMBED_MODEL     = _m("embed",    "nomic-embed-text")
# Embedding always runs locally — nomic-embed-text is a local lightweight model.
# Independent of the remote/local LLM switch so memory works even in remote mode.
EMBED_BASE_URL  = _models_cfg.get("embed_base_url", "http://localhost:11434")

OLLAMA_BASE_URL = _models_cfg.get("ollama_base_url", "http://localhost:11434")

# API-Key normalisieren: Whitespace strippen und bekannte Platzhalter als
# "kein Key" behandeln. Verhindert dass ein kopierter Example-Platzhalter
# versehentlich Remote-Mode aktiviert (führt sonst zu HTTP 401 unauthorized).
_PLACEHOLDER_KEYS = {"", "DEIN_API_KEY_HIER", "YOUR_API_KEY_HERE", "CHANGE_ME"}
_raw_api_key    = (_models_cfg.get("ollama_api_key", "") or "").strip()
OLLAMA_API_KEY  = "" if _raw_api_key in _PLACEHOLDER_KEYS else _raw_api_key
if _raw_api_key in _PLACEHOLDER_KEYS and _raw_api_key != "":
    print(f"[config] ollama_api_key ist Platzhalter ('{_raw_api_key}') → Local-Mode")

# Temperaturen je Agent-Typ
TEMP_ANALYSIS   = 0.3   # Blue Agent, Red Agent, Reporter
TEMP_CODE       = 0.2   # Coding Agent
TEMP_RESEARCH   = 0.1   # Research Agent, Tool-Selektion

# ─── Local-Fallback-Modelle (genutzt wenn kein OLLAMA_API_KEY gesetzt) ────────

LOCAL_MODEL_ANALYSIS = _ml("analysis", "qwen2.5-coder:14b")
LOCAL_MODEL_CODE     = _ml("code",     "qwen2.5-coder:14b")
LOCAL_MODEL_RESEARCH = _ml("research", "qwen2.5:7b")
# Planner braucht kein großes Modell — Task-Reihenfolge/Parameter, keine Analyse.
# Default: gleiches Modell wie Research (7B lokal), überschreibbar via models.json.
LOCAL_MODEL_PLANNER  = _ml("planner",  LOCAL_MODEL_RESEARCH)
# Planning LLM always runs locally — Ollama's native tool-calling API works reliably
# with local qwen2.5:7b. Remote models (gpt-oss) return None/empty from the
# experimental executor's call_llm_native_tools (native function-calling not supported
# reliably via the remote Ollama endpoint).
PLANNER_BASE_URL     = "http://localhost:11434"

# ─── Aktive LLM-Konfiguration (Remote oder Local) ─────────────────────────────

if OLLAMA_API_KEY:
    ACTIVE_BASE_URL  = OLLAMA_BASE_URL
    ACTIVE_ANALYSIS  = MODEL_ANALYSIS
    ACTIVE_CODE      = MODEL_CODE
    ACTIVE_RESEARCH  = MODEL_RESEARCH
    ACTIVE_PLANNER   = _m("planner", MODEL_ANALYSIS)   # Remote: Default = Analysis
else:
    ACTIVE_BASE_URL  = "http://localhost:11434"
    ACTIVE_ANALYSIS  = LOCAL_MODEL_ANALYSIS
    ACTIVE_CODE      = LOCAL_MODEL_CODE
    ACTIVE_RESEARCH  = LOCAL_MODEL_RESEARCH
    ACTIVE_PLANNER   = LOCAL_MODEL_PLANNER              # Local: Default = 7B

# ─── Pfade ────────────────────────────────────────────────────────────────────

PROJECT_DIR      = os.path.dirname(os.path.abspath(__file__))   # recon-suite/agentscanit/
_SUITE_DIR       = os.path.dirname(PROJECT_DIR)                  # recon-suite/

# Shared outputs → recon-suite level (alle Teams schreiben in dieselben Verzeichnisse)
LOG_DIR          = os.path.join(_SUITE_DIR,  "logs")
SCAN_DIR         = os.path.join(_SUITE_DIR,  "scans")

# Team-spezifisch → agentscanit level (LanceDB-Memory bleibt beim Team)
MEMORY_DIR       = os.path.join(PROJECT_DIR, "memory")
KNOWLEDGE_DIR    = os.path.join(PROJECT_DIR, "knowledge_storage")
TEMP_DIR         = os.path.join(PROJECT_DIR, "temp")
THEHARVESTER_DIR = os.path.join(PROJECT_DIR, "theHarvester")
TESTSSL_DIR      = os.path.join(PROJECT_DIR, "testssl.sh")
ENUM4LINUX_DIR   = os.path.join(PROJECT_DIR, "enum4linux-ng")

# ─── Tool-Binaries ────────────────────────────────────────────────────────────

VENV_PYTHON        = os.path.join(PROJECT_DIR, "venv", "bin", "python3")

# Go-Binary-Verzeichnis: GOPATH/bin ermitteln, Fallback auf ~/go/bin
def _go_bin() -> str:
    try:
        import subprocess as _sp
        gopath = _sp.check_output(["go", "env", "GOPATH"], text=True,
                                  timeout=5).strip()
        if gopath:
            return os.path.join(gopath, "bin")
    except Exception:
        pass
    return os.path.join(os.path.expanduser("~"), "go", "bin")

GO_BIN             = _go_bin()

# System-PATH
NMAP_BIN           = "nmap"
NIKTO_BIN          = "nikto"
WHATWEB_BIN        = "whatweb"
SSLSCAN_BIN        = "sslscan"
FFUF_BIN           = "ffuf"
SUBLIST3R_BIN      = "sublist3r"
DNSRECON_BIN       = "dnsrecon"
HTTPX_BIN          = "/snap/bin/httpx"
WHOIS_BIN          = "whois"
DIG_BIN            = "dig"
PING_BIN           = "ping"
CURL_BIN           = "curl"

# Go-Binaries
NUCLEI_BIN         = os.path.join(GO_BIN, "nuclei")
AMASS_BIN          = os.path.join(GO_BIN, "amass")
ASSETFINDER_BIN    = os.path.join(GO_BIN, "assetfinder")
SUBFINDER_BIN      = os.path.join(GO_BIN, "subfinder")
NAABU_BIN          = os.path.join(GO_BIN, "naabu")
DNSX_BIN           = os.path.join(GO_BIN, "dnsx")
KATANA_BIN         = os.path.join(GO_BIN, "katana")
WAYBACKURLS_BIN    = os.path.join(GO_BIN, "waybackurls")
GAU_BIN            = os.path.join(GO_BIN, "gau")

# Externe Skripte
TESTSSL_BIN        = os.path.join(TESTSSL_DIR, "testssl.sh")
ENUM4LINUX_BIN     = os.path.join(ENUM4LINUX_DIR, "enum4linux-ng.py")
SEARCHSPLOIT_BIN   = "/usr/local/bin/searchsploit"

# ─── Timeouts (Sekunden) ──────────────────────────────────────────────────────

TIMEOUT_DEFAULT    = 300
TIMEOUT_NMAP_DISC  = 360
TIMEOUT_NMAP_SCAN  = 180   # -A removed; -sV on top-1000 finishes well under 3min
TIMEOUT_NIKTO      = 120   # nikto gets -maxtime 90s, 120s is the safety fallback
TIMEOUT_TESTSSL    = 300
TIMEOUT_NUCLEI     = 180
TIMEOUT_SHORT      = 30
TIMEOUT_MEDIUM     = 120

# ─── Output-Limits (Zeichen) ──────────────────────────────────────────────────

OUTPUT_LIMITS = {
    "default":      3000,
    "nmap":         4000,
    "nikto":        4000,
    "testssl":      4000,
    "ffuf":         3000,
    "nuclei":       4000,
    "sublist3r":    3000,
    "subfinder":    3000,
    "sslscan":      3000,
    "dnsrecon":     3000,
    "theharvester": 3000,
    "whois":        2000,
    "whatweb":      2000,
    "httpx":        3000,
    "amass":        3000,
    "assetfinder":  2000,
    "enum4linux":   4000,
}

# ─── Wordlists ────────────────────────────────────────────────────────────────

WORDLIST_DEFAULT   = "/usr/share/dirb/wordlists/common.txt"

# ─── Verzeichnisse anlegen ────────────────────────────────────────────────────

for _d in (LOG_DIR, SCAN_DIR, MEMORY_DIR, KNOWLEDGE_DIR, TEMP_DIR):
    os.makedirs(_d, exist_ok=True)

# ─── Umgebungsvariablen ───────────────────────────────────────────────────────

os.environ["CREWAI_DISABLE_TELEMETRY"]       = "true"
os.environ["OTEL_SDK_DISABLED"]              = "true"
os.environ["EMBEDDINGS_OLLAMA_MODEL_NAME"]   = EMBED_MODEL
os.environ["CREWAI_STORAGE_DIR"]             = KNOWLEDGE_DIR

# Route all LLM calls (including CrewAI Memory's internal reconstruction) to
# the active Ollama endpoint. Memory rebuilds its LLM from a plain model-name
# string (no base_url). The OpenAI SDK v2 reads OPENAI_BASE_URL from env when
# no explicit base_url is passed. /v1 must be included in the path.
_base_url_v1 = ACTIVE_BASE_URL.rstrip("/") + "/v1"
if OLLAMA_API_KEY:
    os.environ["OPENAI_BASE_URL"] = _base_url_v1
    os.environ["OPENAI_API_KEY"]  = OLLAMA_API_KEY
else:
    os.environ["OPENAI_API_KEY"]  = "dummy"  # suppress litellm warning, local only

# ─── Startup-Meldung ──────────────────────────────────────────────────────────

if OLLAMA_API_KEY:
    print(f"[config] LLM: Remote  {OLLAMA_BASE_URL}")
else:
    print("[config] LLM: Local   http://localhost:11434")
