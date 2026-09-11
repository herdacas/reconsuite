# Konzept: Recon-Suite inkl. Tools als Docker-Image

**Status:** Konzept / Diskussionsgrundlage — NICHT umgesetzt, kein Build.
**Datum:** 2026-06-26
**Kontext:** Ausgelöst durch die Erkenntnis, dass die Suite beim Scan aktiv auf Binaries
**außerhalb** des Projektordners zugreift (System-PATH, `/snap/bin`, `/root/go/bin`,
`/usr/local/bin`) → Reproduzierbarkeit hängt an der Host-Systemstruktur, nicht am Projekt.

---

## 1. Problem, das ein Image löst

Aktuell sind die Scan-Tools über drei Orte verstreut (faktisch aus `agentscanit/config.py`):

| Schicht | Tools | Pfad (Host, aktuell) |
|---|---|---|
| System-PATH (apt) | nmap, nikto, whatweb, sslscan, dig, whois, curl, ping | `/usr/bin/*` |
| Absolut hart kodiert | searchsploit | `/usr/local/bin/searchsploit` |
| Absolut hart kodiert | httpx | `/snap/bin/httpx` (Snap!) |
| Go (`GOPATH/bin`) | nuclei, subfinder, dnsx, katana (+ naabu/amass/… ungenutzt) | `/root/go/bin/*` |
| Im Projekt (optional) | testssl.sh, enum4linux-ng | `agentscanit/<repo>/…` (aktuell nicht installiert) |
| Python-Deps | crewai etc. | `recon-suite/venv` (936 MB) |
| WAF (neu) | wafw00f | `recon-suite/venv/bin/wafw00f` (nur bei aktivem venv im PATH) |

**Folge:** „Projekt kopieren" reicht NICHT — auf einer anderen Maschine brechen Scans, wenn
httpx nicht unter `/snap/bin` liegt, `GOPATH` nicht `/root/go` ist, oder apt-Tools fehlen.
`setup_tools.sh` mildert das (installiert die 18 System-Binaries), ist aber ein
Host-Setup-Schritt, kein abgeschlossenes Artefakt.

Ein Image **friert alle drei Schichten ein** → „läuft überall gleich".

---

## 2. Was rein müsste (3 Build-Schichten)

1. **System-Tools (apt):** `nmap nikto whatweb sslscan dnsutils whois curl iputils-ping wafw00f`
2. **Go-Tools (`go install`):** nuclei, subfinder, dnsx, katana — Build legt sie an einen
   **deterministischen** `GOPATH/bin` → kein `/root/go`-Rätsel mehr.
3. **Python:** Python 3.12 + `requirements.txt` (vorhanden) in ein venv ODER system-weit im Image.

Plus: searchsploit/Exploit-DB (s. Haken 2), die Suite selbst (`COPY`), Entrypoint.

---

## 3. Die ehrlichen Haken (projektspezifisch, NICHT generisch)

1. **httpx kommt aus Snap.** Snap läuft in Docker schlecht (braucht snapd/systemd). Im Image
   httpx stattdessen per `go install github.com/projectdiscovery/httpx/...` holen →
   **`HTTPX_BIN` in config.py ändert sich** von `/snap/bin/httpx` auf den Go-Pfad. Kleiner,
   aber nötiger Eingriff. (httpx hier = ProjectDiscovery-Go, NICHT Python-httpx — siehe CLAUDE.md.)

2. **searchsploit braucht die Exploit-DB** (Git-Repo, mehrere hundert MB). Optionen:
   - reinbacken → großes Image, aber selbstständig
   - als Volume mounten → kleineres Image, aber nicht mehr autark
   - `searchsploit --update` beim Build → reproduzierbar, aber langer Build

3. **LLM-Verbindung bleibt außerhalb des Containers.**
   - Remote-Ollama (`ollama.com`, aktueller Worker `qwen3-coder:480b`): funktioniert aus dem
     Container direkt (Internet).
   - **Lokales Ollama** (`localhost:11434`, u.a. der Planner `qwen2.5:7b`!): liegt auf dem Host →
     im Container ist `localhost` NICHT der Host. Lösung: `OLLAMA_BASE_URL=http://host.docker.internal:11434`
     (bzw. `--add-host`/`--network host`). **Wichtig:** der Planner läuft IMMER lokal (CLAUDE.md) →
     ohne diese Brücke kein Planning. Reine Config, kein Blocker.

4. **Image-Größe realistisch 2–4 GB.** venv allein 936 MB + Go-Tools + apt + ggf. Exploit-DB.
   Normal für eine Pentest-Tool-Suite (vgl. Kali-Container), aber kein Leichtgewicht.
   Multi-Stage-Build (Go-Tools in Builder-Stage, nur Binaries kopieren) drückt das etwas.

5. **Scan-Outputs müssen ein Volume sein.** `logs/` (Reports, Traces, `flow_state.db`,
   `workflow_last.json`) sonst nach Container-Stop weg. Mount: `-v ./logs:/app/logs`.
   `LOG_DIR`/`SCAN_DIR` liegen auf Suite-Ebene (config.py) → ein Volume-Mount reicht.

6. **config.py-Pfade image-tauglich machen.** Betroffen sind genau die absolut-hart-kodierten:
   `HTTPX_BIN`, `SEARCHSPLOIT_BIN`. Im Image deterministisch → entweder feste Image-Pfade
   eintragen ODER (robuster, s. offener Punkt unten) `shutil.which` mit Fallback. `GO_BIN` ist
   schon dynamisch (`go env GOPATH`) → im Image automatisch korrekt.

---

## 4. Skizzierte Dockerfile-Struktur (Pseudocode, nicht getestet)

```dockerfile
# ---- Stage 1: Go-Tools bauen ----
FROM golang:1.22 AS gobuild
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest   # ersetzt Snap-httpx

# ---- Stage 2: Laufzeit ----
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap nikto whatweb sslscan dnsutils whois curl iputils-ping wafw00f git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gobuild /go/bin/* /usr/local/bin/        # Go-Tools an festen Ort
# searchsploit / exploitdb (Haken 2): git clone + symlink ODER Volume
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
WORKDIR /app
# LLM via Env (host.docker.internal für lokales Ollama, Haken 3)
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434
VOLUME /app/logs
ENTRYPOINT ["python3", "main.py"]
```

Lauf-Beispiel:
```
docker run --rm -v $(pwd)/logs:/app/logs \
  --add-host=host.docker.internal:host-gateway \
  recon-suite example.com web
```

---

## 5. Der eigentliche Gewinn (über Portabilität hinaus)

Passt zum bestehenden **Verifikations-Harness** (`testing/`, lokal): das startet bereits
VulHub-Docker-Container als Scan-**Targets**. Ein Suite-Image würde „Scanner-Container scannt
Target-Container" sauber zusammenführen → reproduzierbare Matrix-Läufe (TESTKONZEPT.md) ohne
„läuft nur auf meiner Maschine". Docker-Compose-Netz: Suite + Target im selben Netzwerk.

---

## 6. Aufwand-Einschätzung

**Moderat**, kein Neubau — die Bausteine existieren:
- `setup_tools.sh` ist faktisch schon die halbe apt-/go-Logik der Dockerfile.
- `requirements.txt` vorhanden.
- Nur 2–3 Pfad-Konstanten (`HTTPX_BIN`, `SEARCHSPLOIT_BIN`) müssen image-tauglich werden.

**Echte Stolpersteine:** httpx/Snap → Go (Haken 1), lokales Ollama-Bridging (Haken 3),
Exploit-DB-Größe (Haken 2). Alle lösbar, keiner ein Blocker.

---

## 7. Offener Folgepunkt (unabhängig vom Image, aber synergetisch)

Die hart kodierten absoluten Pfade (`HTTPX_BIN = "/snap/bin/httpx"`,
`SEARCHSPLOIT_BIN = "/usr/local/bin/searchsploit"`) sind schon OHNE Docker fragil. Sie auf
`shutil.which(<name>)` mit Fallback auf den bekannten Pfad umzustellen, würde Portabilität
sofort erhöhen — und macht die Dockerisierung (Punkt 6) einfacher, weil die Pfade dann im
Image automatisch stimmen. Separat umsetzbar, reine Code-Härtung.

> Reine Dokumentation, nicht umgesetzt. Bausteine: [setup_tools.sh] (committet),
> requirements.txt, agentscanit/config.py (Pfad-Konstanten).
