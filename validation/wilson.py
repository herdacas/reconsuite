"""validation/wilson.py — Wilson-Score-Konfidenzintervall (95%), keine scipy-Abhängigkeit.

VALIDATION_SPEC.md Phase 3: 'Eine nackte Prozentzahl ist ungültig' — jede Quote
braucht Intervall + Stichprobengröße. Geschlossene Formel, keine externe Lib nötig.
"""
import math

_Z95 = 1.959963985  # z-Wert für 95%-Konfidenz


def wilson_ci(successes: int, n: int, z: float = _Z95) -> dict:
    """Gibt {'p': p_hat, 'lower': ..., 'upper': ..., 'n': n} zurück.
    n=0 -> alle Werte None (keine Aussage möglich, NICHT 0.0 vortäuschen)."""
    if n == 0:
        return {"p": None, "lower": None, "upper": None, "n": 0}
    p_hat = successes / n
    denom = 1 + z * z / n
    center = p_hat + z * z / (2 * n)
    margin = z * math.sqrt((p_hat * (1 - p_hat) / n) + (z * z / (4 * n * n)))
    lower = max(0.0, (center - margin) / denom)
    upper = min(1.0, (center + margin) / denom)
    return {"p": round(p_hat, 4), "lower": round(lower, 4), "upper": round(upper, 4), "n": n}


if __name__ == "__main__":
    print(wilson_ci(9, 10))
    print(wilson_ci(0, 0))
