# Benchmark-Anforderungen: Lokales LLM für agentic Recon-Scans

**Zweck:** Spezifikation zum Einpflegen in einen bestehenden LLM-Performance-Testlauf.
Definiert, welche Kennzahlen ein lokales Modell erfüllen muss, um in einem agentic
Multi-Agent-Scan-Framework (CrewAI + Ollama, native Function-Calling, mehrstufige
Tool-Orchestrierung) produktiv einsetzbar zu sein.

**Kontext für den Coding-Agent:** Das Zielsystem ist KEIN Single-Prompt-Chatbot, sondern eine
Pipeline aus mehreren Agenten, die in tiefen Multi-Turn-Konversationen wiederholt Tools aufrufen
(Tool-Call → Tool-Result → nächster Tool-Call). Ein Scan besteht aus ~5 Phasen mit jeweils
mehreren LLM-Calls. Tauglichkeit entscheidet sich im Multi-Turn-Tool-Kontext, nicht am Einzel-Call.

---

## A. Harte K.O.-Kriterien (eines verfehlt → Modell unbrauchbar)

| # | Kriterium | Schwelle |
|---|---|---|
| 1 | Natives Function-Calling (Ollama tool-calling API) | muss zuverlässig vorhanden sein |
| 2 | Leerantwort-Rate im Multi-Turn (≥10 Messages Verlauf) | < 1 % (Ziel 0 %) |
| 3 | Non-Reasoning ODER `think:False`-konform | Pflicht (kein Antwortverlust im thinking-Kanal) |
| 4 | Tool-Input-Sauberkeit | keine verstümmelten Argumente (z. B. `?`, `://://`, abgeschnittene Targets) |

## B. Performance-Schwellen (Durchsatz / Latenz)

| # | Kennzahl | Mindestwert |
|---|---|---|
| 5 | Generierungsdurchsatz (tokens/s) | ≥ 25 tok/s (besser ≥ 40) |
| 6 | Latenz pro Worker-Call | < 30 s |
| 7 | Prefill / Prompt-Verarbeitung | ~10–18k Tokens zügig (ohne Minuten-Latenz) |
| 8 | Kontextfenster (Worker) | ≥ 8k Tokens (16k empfohlen) |

## C. Ziel-Gesamtlaufzeit

- Ein vollständiger Scan-Durchlauf (~5 Phasen, mehrere Tool-Calls je Phase) soll **< 30 min**
  end-to-end bleiben. Darüber gilt das Modell als praktisch unbrauchbar, auch wenn es A erfüllt.

---

## D. Drei Punkte, die der Benchmark BESONDERS beachten muss

Ohne diese drei Prüfungen liefert ein naiver Benchmark falsch-positive Ergebnisse:

1. **Multi-Turn statt Einzel-Call testen.**
   Manche Modelle bestehen isolierte Einzel-Calls, brechen aber in tiefen Tool-Ketten ein
   (Leerantworten häufen sich mit steigender Message-Zahl). Test-Pattern: System-Prompt +
   mindestens 6 abwechselnde Tool-Call/Tool-Result-Paare + abschließender Turn. Gemessen wird
   das Verhalten am Ende der Kette, nicht am ersten Call.

2. **tok/s bei realistischer Prompt-Größe messen.**
   Durchsatz mit echten Prompt-Größen (~10–18k Zeichen), nicht mit Mini-Prompts ("Hello world").
   Latenz/Durchsatz brechen bei großen Recon-Prompts oft drastisch ein — genau das ist der reale
   Lastfall.

3. **Tool-Coupling prüfen, nicht nur Sprachausgabe.**
   Ein Modell kann flüssig und ohne Leerantworten antworten und trotzdem die erwarteten Tool-Calls
   NICHT erzeugen (z. B. beschreibt einen Scan in Prosa, statt das Scan-Tool aufzurufen). Der
   Benchmark muss verifizieren, dass bei einer tool-pflichtigen Aufgabe tatsächlich der korrekte
   Function-Call ausgelöst wird — sonst wird ein faktisch nutzloses Modell als tauglich gewertet.

---

## E. Empfohlene Auswertungs-Matrix (pro Modell)

| Modell | FC vorhanden | Leerantw.-% (Multi-Turn) | tok/s @ realer Prompt | Latenz/Call | Tool-Call korrekt ausgelöst | E2E-Laufzeit | Tauglich? |
|---|---|---|---|---|---|---|---|

Tauglich = alle K.O.-Kriterien (A) erfüllt UND Performance-Schwellen (B) UND Gesamtlaufzeit (C)
UND alle drei D-Prüfungen bestanden.
