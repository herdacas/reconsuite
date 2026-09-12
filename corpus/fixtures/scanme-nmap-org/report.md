**Target:** scanme.nmap.org  
**Objective:** Full vulnerability assessment of scanme.nmap.org  
**Scope:** full  
**Date:** 2026-09-10 22:34

---

# Recon Report: scanme.nmap.org
## Reconnaissance Summary
  Target IP: 45.33.32.156
  Open ports: 22, 80, 9929, 31337
  Services detected:
    - Port 80: Apache httpd 2.4.7
    - Port 22: OpenSSH 6.6.1p1
    - Port 9929: Informational Nping echo service
    - Port 31337: Informational tcpwrapped service

## Scope & Methodik
| Tool | Purpose | Covered Assets |
|------|---------|----------------|
| nmap -p 1-65535 -T4 scanme.nmap.org | Full port scan | All 1-65535 ports |
| nmap -p 22,80,9929,31337 -sV -T4 scanme.nmap.org | Service/version detection | Ports 22,80,9929,31337 |
| whatweb http://scanme.nmap.org | Web server fingerprinting | HTTP service |
| httpx -targets scanme.nmap.org -options -api_probe=false | HTTP/HTTPS probe | scanme.nmap.org |
| wafw00f https://scanme.nmap.org | WAF detection | HTTPS endpoint |
| nikto -target http://scanme.nmap.org -port 80 -tuning 4 | Vulnerability & misconfig scan | Port 80 |
| curl_http_headers -url https://scanme.nmap.org -follow_redirects true | Header analysis | HTTPS endpoint |

## Confirmed Findings
| Service | Port | Observation | Tool | Trace-Seq# |
|---------|------|-------------|------|------------|
| Apache httpd | 80 | Apache 2.4.7 version disclosed in Server header | nmap (step_2) | 2 |
| OpenSSH | 22 | OpenSSH 6.6.1p1 version disclosed | nmap (step_2) | 2 |
| HTTP | 80 | Missing X-Frame-Options header | nikto (step_6) | 6 |
| npings | 9929 | Informational Nping echo service on port 9929 | nmap (step_1) | 1 |
| tcpwrapped | 31337 | Informational tcpwrapped service on port 31337 | nmap (step_2) | 2 |

## Detected Technologies
Server header: Apache 2.4.7 → Apache 2.4.7
whatweb → Apache 2.4.7
nmap service detection → OpenSSH 6.6.1p1

## CVE References
[Leave empty]