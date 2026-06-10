# Debugging Suite

Schnelle Isolation von Problemen ohne vollen Scan-Durchlauf.

## Schritt 1 — LLM + Native-FC testen (< 2 min)
```bash
cd /opt/projects/agentic-ai/recon-suite
python3 debugging/check_llm.py
```
Zeigt: Welches Modell antwortet, ob tool_calls funktionieren, ob `think=False` stört.

## Schritt 2 — Tools einzeln testen (< 10 min)
```bash
python3 debugging/check_tools.py testphp.vulnweb.com
```
Zeigt: Laufzeit pro Tool, welche Tools timeout-en oder fehlschlagen.
Langsame Tools (>60s) → Kandidaten zum Rausschmeißen.

## Schritt 3 — Einzelnen Agent testen (< 5 min)
```bash
python3 debugging/check_agent.py research testphp.vulnweb.com
python3 debugging/check_agent.py blue    testphp.vulnweb.com
```
Zeigt: Ob CrewAI + AgentExecutor + LLM zusammenarbeiten.

## Schritt 4 — Minimaler Scan (osint scope, < 5 min)
```bash
python3 flow.py testphp.vulnweb.com osint
```
Nur research + report, kein Active Scanning. Schnellster End-to-End Test.
