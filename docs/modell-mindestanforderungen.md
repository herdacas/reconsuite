# Modell-Mindestanforderungen (lokaler Worker) + Lokal-Achse-Abschluss

**Status:** Referenz für das externe LLM-Benchmark. Lokal, nicht gepusht.
**Datum:** 2026-06-26
**Kontext:** Lokal-Achse des Testkonzepts. Letzter Benchmark-Durchlauf des Nutzers entscheidet,
ob ein lokales Modell produktiv taugt. Danach Lokal-Achse abgeschlossen (Entscheidung Nutzer:
„lohnt sich nicht weiter") — Remote (qwen3-coder:480b) bleibt der verlässliche Pfad.

---

## A. Harte K.O.-Kriterien (nicht erfüllt → unbrauchbar)

| # | Kriterium | Schwelle | Beleg |
|---|---|---|---|
| 1 | Natives Ollama Function-Calling | vorhanden | AgentExecutor nutzt call_llm_native_tools; reine Chat-Modelle scheitern |
| 2 | Leerantwort-Rate (Multi-Turn ≥10 msgs) | < 1 % (Ziel 0) | gpt-oss:120b 6.7 % → untauglich (BUG-19); 8B in dieser Session 0 % |
| 3 | Non-Reasoning ODER think:False-konform | Pflicht | Reasoning-Modelle verlieren Antwort im thinking-Kanal bei tiefen FC-Ketten |
| 4 | Tool-Input-Sauberkeit | keine verstümmelten Targets | qwen3-coder 31/31 sauber; gpt-oss vereinzelt verstümmelt |

## B. Performance-Schwellen (DAS Problem auf dieser Hardware)

| # | Kennzahl | Mindest | Begründung (gemessen) |
|---|---|---|---|
| 5 | Generierung tok/s | ≥ 25, besser ≥ 40 | 8B-Läufe: ~250s/Call bei ~150 Tok resp = ~0.6 tok/s effektiv → Abbruch |
| 6 | Latenz pro Worker-Call | < 30 s | gemessen 190–252 s/Call → Scan >70 min bzw. Abbruch |
| 7 | Prefill (Prompt-Verarbeitung) | ~10–18k Tok zügig | größter realer Worker-Prompt ~31k chars (~8k Tok) |
| 8 | Kontextfenster (Worker) | ≥ 8k Tok (16k empf.) | reale Prompts ~8–18k chars |

## C. Ziel-Gesamtlaufzeit
- Remote-Referenz (qwen3-coder:480b): network-Scan ~13–15 min, voll funktionsfähig.
- Lokal akzeptabel: network-Scan **< 30 min** E2E. Darüber praktisch unbrauchbar.

## D. Was ein Benchmark zusätzlich prüfen MUSS (sonst falsch-positiv)
1. **Multi-Turn statt Einzel-Call** — gemma4:e2b/gpt-oss bestehen Einzel-Calls, scheitern im Scan.
   Pattern: System-Prompt + ~6 Tool-Call/Result-Paare + Abschluss-Turn.
2. **tok/s bei realer Prompt-Größe** (~10–18k chars), nicht „Hello world".
3. **Tool-Coupling** — llama3.1:8b lief mit 0 % Leerantworten durch, rief aber in blue KEIN
   Scan-Tool auf (Coverage 0/100). Reiner Speed/Leer-Benchmark hätte es falsch als tauglich gewertet.

---

## E. Lokal-Achse — Ergebnis bisher (3 Modelle, diese Session)

| Modell | Leerantw. | E2E | Tool-Coverage | Laufzeit | Urteil |
|---|---|---|---|---|---|
| qwen3-coder:30b | — | ❌ erfolglos (Nutzer) | — | — | HW-Grenze (VRAM/Speed) |
| llama3.1:8b @ scanme | 0 % | ✅ durch | 0/100 (blue ohne Scan-Tools) | 71 min | läuft, aber wertlos |
| llama3-groq:8b @ Tomcat | 0 % | ❌ Abbruch in research→blue | nie erreicht | >60 min, 0 Artefakte | zu langsam |

**Schluss:** Framework ist lokal-fähig (0 Leerantworten, Halluzinationen korrekt gefiltert —
scanme: WebLogic-Fake-CVEs → Final Report 0 CVEs). Aber die verfügbaren lokalen Modelle/Hardware
reichen für produktive Scans nicht (Speed + agentic Tool-Coverage). **Remote qwen3-coder:480b
bleibt der verlässliche Pfad.** Nach dem letzten Benchmark-Durchlauf: Lokal-Achse abgeschlossen.
