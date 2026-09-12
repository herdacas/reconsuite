**Target:** 172.17.0.2  
**Date:** 2026-09-12 04:23  
**Source:** AgentScanIT scan + NVD API v2

---

# Final Report: 172.17.0.2

## Reconnaissance Summary
- IP: 172.17.0.2
- Open ports: 22/tcp, 80/tcp, 443/tcp
- Services: OpenSSH 8.9p1 Ubuntu 3ubuntu0.1, Apache 2.4.54 (Ubuntu), nginx 1.31.2

## Scope & Methodik
| Tool | Zweck | Abgedeckte Assets |
|------|-------|-------------------|
| dig | DNS-Auflösung | 172.17.0.2 |
| httpx | HTTP-Probing | 172.17.0.2:80, 172.17.0.2:443 |
| nmap | Port- und Service-Scanning | 172.17.0.2 |
| whatweb | Web‑Technologie‑Fingerprinting | 172.17.0.2 |
| searchsploit | CVE‑Lookup | 172.17.0.2 |
| whois | WHOIS‑Abfrage | 172.17.0.2 |

## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|------------|
| OpenSSH | 22 | OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 | nmap | 1 |
| Apache httpd | 80 | Apache 2.4.54 (Ubuntu) | nmap | 2 |
| nginx | 443 | nginx 1.31.2 | nmap | 3 |
| Login page | 80 | Login page at /login (200 OK) | httpx | 4 |
| CMS detection | 80 | Drupal CMS 9.3.0 identified | whatweb | 5 |

## Detected Technologies
whatweb_fingerprint → OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
whatweb_fingerprint → Apache 2.4.54 (Ubuntu)
whatweb_fingerprint → nginx 1.31.2
whatweb_fingerprint → Drupal CMS 9.3.0

## CVE Validation (NVD API v2)

*Source: https://nvd.nist.gov — 2026-09-12 04:23*

- Gelistet: **0**  Critical: **0**  High: **0**
