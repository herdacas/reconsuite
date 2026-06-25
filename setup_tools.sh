#!/usr/bin/env bash
#
# setup_tools.sh — installiert die externen Scan-Tools die AgentScanIT als
# System-Binaries voraussetzt (NICHT in requirements.txt, da keine Python-Pakete).
#
# Zielplattform: Kali / Debian / Ubuntu (apt + Go + Git).
# Idempotent: prüft pro Tool ob bereits vorhanden (which), installiert nur fehlende,
# bricht bei einem Fehlschlag NICHT ab — meldet am Ende welche Tools fehlen.
#
# Verwendung:
#   sudo bash setup_tools.sh          # volle Installation
#   bash setup_tools.sh --check       # nur prüfen, nichts installieren
#
set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

GO_BIN="${HOME}/go/bin"
EXPLOITDB_DIR="/opt/exploitdb"
MISSING=()
INSTALLED=()
FAILED=()

# ─── Die 18 aktiven Tools (siehe agents.py / CLAUDE.md) ──────────────────────
# Tools die das Framework tatsächlich aufruft. testssl/enum4linux/theHarvester
# sind in den Tool-Listen deaktiviert → hier nicht enthalten.
APT_TOOLS=(nmap nikto whatweb sslscan dnsrecon whois curl iputils-ping bind9-dnsutils)
#   bind9-dnsutils liefert 'dig'; iputils-ping liefert 'ping'
GO_TOOLS=(
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
)

_have() { command -v "$1" >/dev/null 2>&1; }

log()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }

echo "=== AgentScanIT — Tool-Setup (Kali/Debian/Ubuntu) ==="
[[ $CHECK_ONLY == 1 ]] && echo "(--check: nur prüfen, keine Installation)"

# ─── 1. apt-Tools ────────────────────────────────────────────────────────────
echo; echo "── apt-Tools ──"
APT_NEEDED=()
declare -A APT_PROVIDES=([bind9-dnsutils]=dig [iputils-ping]=ping)
for pkg in "${APT_TOOLS[@]}"; do
  bin="${APT_PROVIDES[$pkg]:-$pkg}"
  if _have "$bin"; then ok "$bin (vorhanden)"; else APT_NEEDED+=("$pkg"); fi
done
if [[ ${#APT_NEEDED[@]} -gt 0 ]]; then
  if [[ $CHECK_ONLY == 1 ]]; then
    for p in "${APT_NEEDED[@]}"; do warn "$p (fehlt — würde via apt installiert)"; MISSING+=("$p"); done
  else
    log "Installiere via apt: ${APT_NEEDED[*]}"
    if apt-get update -qq && apt-get install -y -qq "${APT_NEEDED[@]}"; then
      for p in "${APT_NEEDED[@]}"; do ok "$p installiert"; INSTALLED+=("$p"); done
    else
      for p in "${APT_NEEDED[@]}"; do err "$p fehlgeschlagen"; FAILED+=("$p"); done
    fi
  fi
fi

# ─── 2. Go-Tools (ProjectDiscovery) ──────────────────────────────────────────
# WICHTIG: httpx hier = ProjectDiscovery (Go), NICHT das apt-Paket 'httpx' (Python-CLI)!
echo; echo "── Go-Tools (ProjectDiscovery) ──"
if ! _have go; then
  warn "Go nicht installiert — Go-Tools können nicht gebaut werden."
  [[ $CHECK_ONLY == 0 ]] && warn "Installiere Go: https://go.dev/doc/install (apt install golang-go ODER offizielles Tarball)"
fi
export PATH="$PATH:$GO_BIN:/usr/local/go/bin"
for entry in "${GO_TOOLS[@]}"; do
  bin="${entry%%:*}"; pkg="${entry#*:}"
  if _have "$bin"; then ok "$bin (vorhanden)"; continue; fi
  if [[ $CHECK_ONLY == 1 ]]; then warn "$bin (fehlt — würde via 'go install' gebaut)"; MISSING+=("$bin"); continue; fi
  if ! _have go; then err "$bin (Go fehlt)"; FAILED+=("$bin"); continue; fi
  log "go install $pkg ..."
  if go install "$pkg" 2>/dev/null && _have "$bin"; then
    ok "$bin installiert (→ $GO_BIN)"; INSTALLED+=("$bin")
  else
    err "$bin (go install fehlgeschlagen)"; FAILED+=("$bin")
  fi
done

# ─── 3. searchsploit (exploitdb, Git) ────────────────────────────────────────
echo; echo "── searchsploit (exploitdb) ──"
if _have searchsploit; then
  ok "searchsploit (vorhanden)"
elif [[ $CHECK_ONLY == 1 ]]; then
  warn "searchsploit (fehlt — würde via git clone nach $EXPLOITDB_DIR installiert)"; MISSING+=("searchsploit")
else
  log "git clone exploitdb → $EXPLOITDB_DIR ..."
  if git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$EXPLOITDB_DIR" 2>/dev/null \
     && ln -sf "$EXPLOITDB_DIR/searchsploit" /usr/local/bin/searchsploit; then
    ok "searchsploit installiert"; INSTALLED+=("searchsploit")
  else
    err "searchsploit (Installation fehlgeschlagen)"; FAILED+=("searchsploit")
  fi
fi

# ─── Zusammenfassung ─────────────────────────────────────────────────────────
echo; echo "═══ Zusammenfassung ═══"
[[ ${#INSTALLED[@]} -gt 0 ]] && ok "Installiert: ${INSTALLED[*]}"
[[ ${#MISSING[@]}   -gt 0 ]] && warn "Fehlt (Check-Modus): ${MISSING[*]}"
[[ ${#FAILED[@]}    -gt 0 ]] && err "Fehlgeschlagen: ${FAILED[*]}"
if [[ ${#FAILED[@]} -eq 0 && ${#MISSING[@]} -eq 0 ]]; then
  echo; ok "Alle benötigten Tools vorhanden."
fi

# Hinweis Go-PATH
if [[ -d "$GO_BIN" ]] && ! echo "$PATH" | grep -q "$GO_BIN"; then
  echo; warn "Go-Bin nicht im PATH. Ergänze in ~/.bashrc:  export PATH=\"\$PATH:$GO_BIN\""
fi

# Exit-Code: 0 wenn nichts fehlgeschlagen, sonst 1
[[ ${#FAILED[@]} -eq 0 ]] && exit 0 || exit 1
