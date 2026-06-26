"""OWASP Top 10 (2025) Knowledge Source — aktiviert in Phase 7 (Compliance Mapper).

Genutzt von compliance_agent als Knowledge Source für das OWASP-Mapping.

Aktualisiert 2026-06-26 von 2021 auf die OWASP Top 10:2025 (Quelle: owasp.org/Top10/2025/).
Wesentliche Änderungen 2021 → 2025 (relevant fürs Mapping dieser Suite):
  - A06:2021 'Vulnerable and Outdated Components' → erweitert zu A03:2025 'Software Supply
    Chain Failures'. CVEs auf veralteter Server-Software mappen jetzt auf A03:2025.
  - SSRF (2021 eigenes A10) → 2025 in A01:2025 'Broken Access Control' aufgegangen.
  - Security Misconfiguration A05:2021 → A02:2025 (hochgestuft).
  - Cryptographic Failures A02:2021 → A04:2025; Injection A03:2021 → A05:2025.
  - NEU: A10:2025 'Mishandling of Exceptional Conditions'.
"""

from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

OWASP_TOP10_TEXT = """
# OWASP Top 10 — 2025

A01:2025 – Broken Access Control
Access control enforces policy such that users cannot act outside of their intended
permissions. Failures typically lead to unauthorized information disclosure, modification,
or destruction of data. In 2025 Server-Side Request Forgery (SSRF) has been rolled into
this category.
Key CWEs: CWE-200, CWE-201, CWE-352, CWE-918
Common findings: IDOR, missing auth on admin endpoints, CORS misconfiguration,
  directory traversal, privilege escalation, SSRF (URL fetch without allowlist,
  cloud metadata endpoint 169.254.169.254 accessible).

A02:2025 – Security Misconfiguration
Moved up from #5 (2021) to #2. Missing hardening, unnecessary features enabled, default
accounts/passwords, error handling revealing too much information.
Key CWEs: CWE-16, CWE-611
Common findings: Default credentials, directory listing enabled, verbose error messages,
  unnecessary open ports/services, missing security headers (CSP, HSTS, X-Frame-Options).

A03:2025 – Software Supply Chain Failures
Expansion of A06:2021 'Vulnerable and Outdated Components' to a broader scope: compromises
within or across the entire ecosystem of software dependencies, build systems, and
distribution infrastructure. Outdated/vulnerable components remain a core part of this.
Key CWEs: CWE-1104, CWE-1357
Common findings: Outdated server software (Apache, Nginx, IIS, Tomcat, WebLogic, OpenSSH)
  with known CVEs, outdated CMS, vulnerable libraries (jQuery/OpenSSL CVE), unpatched OS,
  compromised build/distribution pipeline.

A04:2025 – Cryptographic Failures
Failures related to cryptography which often lead to sensitive data exposure or system
compromise. (A02:2021, dropped two spots.)
Key CWEs: CWE-259, CWE-327, CWE-331
Common findings: Weak TLS (SSLv3/TLS 1.0/1.1), self-signed certs, HTTP instead of HTTPS,
  weak cipher suites, hardcoded secrets, insecure hashing (MD5/SHA1).

A05:2025 – Injection
SQL, NoSQL, OS, LDAP injection plus XSS. An application is vulnerable when user-supplied
data is not validated, filtered, or sanitized. (A03:2021, dropped two spots.)
Key CWEs: CWE-79, CWE-89, CWE-73
Common findings: SQL injection, XSS (reflected/stored), command injection, template
  injection, XXE.

A06:2025 – Insecure Design
Risks related to design and architectural flaws — missing or ineffective security controls
by design.
Key CWEs: CWE-209, CWE-256, CWE-501, CWE-522
Common findings: Missing rate limiting, insecure password recovery, business logic flaws.

A07:2025 – Authentication Failures
Previously 'Identification and Authentication Failures'. Confirmation of user identity,
authentication, and session management.
Key CWEs: CWE-297, CWE-287, CWE-384
Common findings: Weak passwords permitted, no MFA, session fixation, insecure session
  tokens, brute force possible, credential stuffing.

A08:2025 – Software or Data Integrity Failures
Assumptions related to software updates, critical data, and CI/CD pipelines without
verifying integrity.
Key CWEs: CWE-829, CWE-494, CWE-502
Common findings: Insecure deserialization, unsigned updates, SRI missing on CDN resources,
  CI/CD without integrity checks.

A09:2025 – Security Logging & Alerting Failures
Previously 'Security Logging and Monitoring Failures'. Without logging and alerting,
breaches cannot be detected or responded to.
Key CWEs: CWE-778, CWE-117, CWE-223, CWE-532
Common findings: No audit log, login failures not logged, no alerting on suspicious
  activity, log injection possible.

A10:2025 – Mishandling of Exceptional Conditions
New category. Improper handling of errors and exceptional/edge conditions leading to
crashes, inconsistent state, information leakage, or security-control bypass.
Key CWEs: CWE-755, CWE-209, CWE-460
Common findings: Unhandled exceptions revealing stack traces, fail-open error paths,
  inconsistent state after partial failure, resource exhaustion on error.

## Mapping Hints

TLS 1.0 / TLS 1.1 / SSLv3              → A04:2025
Self-signed certificate                 → A04:2025
Weak cipher suite                       → A04:2025
CVE (outdated component / server)       → A03:2025
Default credentials                     → A02:2025 + A07:2025
Directory listing                       → A02:2025
Missing security headers (CSP, HSTS)    → A02:2025
Open redirect                           → A01:2025
XSS                                     → A05:2025
SQL injection                           → A05:2025
SSRF                                    → A01:2025
No rate limiting on login               → A07:2025
Verbose error / stack trace leak        → A10:2025
"""

owasp_knowledge = StringKnowledgeSource(
    content=OWASP_TOP10_TEXT,
    metadata={"framework": "OWASP", "version": "2025", "use": "compliance-mapping"},
)
