**Target:** oldenburg.de  
**Objective:** Full vulnerability assessment of oldenburg.de  
**Scope:** full  
**Date:** 2026-09-12 01:43

---

# Recon Report: oldenburg.de

## Reconnaissance Summary
- Live hosts: test.oldenburg.de, mail.test.oldenburg.de
- Open ports: 22, 80, 443

## Scope & Methodik
| Tool | Zweck | Abgedeckte Assets |
|------|-------|-------------------|
| nmap | Netzwerk-Scanning | Ports 22, 80, 443 |
| httpx | HTTP/HTTPS-Probing | Subdomains, Server-Versionen |
| whatweb | Technologie-Fingerprinting | OpenSSH 10.5, nginx |
| sslscan | TLS-Konfiguration | OpenSSL 3.0.13, Legacy-TLS-Versionen |
| curl | HTTP-Header-Analyse | Fehlender HSTS-Header |
| wafw00f | Web-Application-Firewall-Erkennung | Keine WAF erkannt |
| subfinder | Subdomain-Enumeration | test.oldenburg.de, mail.test.oldenburg.de |

## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|-----------|
| OpenSSH | 22 | OpenSSH 10.5 | whatweb | 1 |
| TLS | 443 | OpenSSL 3.0.13 supports legacy TLS versions | sslscan | 2 |
| nginx | 80,443 | Server version not disclosed | httpx | 3 |
| Web Application Firewall | - | No Web Application Firewall detected | wafw00f | 4 |
| HTTP Headers | - | Missing Strict-Transport-Security (HSTS) header | curl | 5 |
| test.oldenburg.de | 443 | Reachable via HTTPS | httpx | 6 |
| mail.test.oldenburg.de | 443 | Reachable via HTTPS | httpx | 7 |

## Detected Technologies
- whatweb → OpenSSH 10.5
- sslscan → OpenSSL 3.0.13
- httpx → nginx

## CVE References

