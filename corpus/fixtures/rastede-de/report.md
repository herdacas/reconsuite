**Target:** rastede.de  
**Date:** 2026-09-11 18:49  
**Source:** AgentScanIT scan + NVD API v2

---

# Final Report: rastede.de

## Reconnaissance Summary
- Target: rastede.de
- Open ports: 21, 22, 25, 53, 80, 106, 110, 143, 443, 465, 993, 995, 4190, 5665, 8443, 8880
- Detected services: Apache httpd (port 80), WordPress 6.6.7 (port 80), additional services on non‑standard ports (8443, 8880, 4190, 5665) – service hypotheses as identified by nmap.

## Scope & Methodik
| Tool | Zweck | Abgedeckte Assets |
|------|-------|-------------------|
| nmap_scanner | Port scanning of listed open ports | rastede.de (ports 21,22,25,53,80,106,110,143,443,465,993,995,4190,5665,8443,8880) |
| httpx_prober | Live HTTP service detection | https://rastede.de |
| whatweb_fingerprint | Web server and technology fingerprinting | rastede.de |
| sslscan_tls | TLS version and cipher inspection | rastede.de |
| nuclei_vulnerability_scanner | Vulnerability scanning with apache and wordpress tags | https://rastede.de |

## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|---------|------|-------------|------|------------|
| Apache httpd | 80 | ActiveMQ < 5.14.0 - Web Shell Upload (Metasploit) | nuclei_vulnerability_scanner | 1 |
| Apache httpd | 80 | Apache 0.8.x/1.0.x / NCSA HTTPd 1.x - 'test-cgi' Directory Listing | nuclei_vulnerability_scanner | 2 |
| Apache httpd | 80 | Apache 1.0/1.2/1.3 - Server Address Disclosure | nuclei_vulnerability_scanner | 3 |
| Apache httpd | 80 | Apache 1.1 / NCSA HTTPd 1.5.2 / Netscape Server 1.12/1.1/2.0 - a nph-test-cgi | nuclei_vulnerability_scanner | 4 |
| Apache httpd | 80 | Apache 1.2.5/1.3.1 / UnityMail 2.0 - MIME Header Denial of Service | nuclei_vulnerability_scanner | 5 |
| Apache httpd | 80 | Apache 1.2 - Denial of Service | nuclei_vulnerability_scanner | 6 |
| Apache httpd | 80 | Apache 1.3.1 | nuclei_vulnerability_scanner | 7 |

## Detected Technologies
- whatweb_fingerprint → Apache httpd
- whatweb_fingerprint → WordPress 6.6.7
- whatweb_fingerprint → Bootstrap 3.4.2
- whatweb_fingerprint → jQuery 3.7.1
- whatweb_fingerprint → Modernizr
- whatweb_fingerprint → OpenSSL 3.0.13
- sslscan_tls → TLS 2.1.2 (OpenSSL 3.0.13)

## CVE Validation (NVD API v2)

*Source: https://nvd.nist.gov — 2026-09-11 18:49*

- Gelistet: **21**  Critical: **13**  High: **5**  ·  1 versionslose generische CVE(s) ausgeblendet

### ✅ Versions-verifizierte CVEs

*Service-Version im Scan erkannt und passt zum betroffenen Produkt.*

### 🟠 CVE-1999-0926 — CVSS 10.0 (HIGH)
- **Published:** 1999-09-03  **Last Modified:** 2026-06-16
- **Vector:** `AV:N/AC:L/Au:N/C:C/I:C/A:C`

**Description:** Apache allows remote attackers to conduct a denial of service via a large number of MIME headers.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:1.2.5:*:*:*:*:*:*:*`

**References:**
- http://archives.neohapsis.com/archives/bugtraq/1998_3/0742.html
- http://archives.neohapsis.com/archives/bugtraq/1998_3/0742.html

### 🔴 CVE-2017-16510 — CVSS 9.8 (CRITICAL)
- **Published:** 2017-11-02  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** WordPress before 4.8.3 is affected by an issue where $wpdb->prepare() can create unexpected and unsafe queries leading to potential SQL injection (SQLi) in plugins and themes, as demonstrated by a "double prepare" approach, a different vulnerability than CVE-2017-14723.

**Affected Products (CPE):**
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`

**References:**
- http://www.securityfocus.com/bid/101638
- https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html
- https://codex.wordpress.org/Version_4.8.3
- https://github.com/WordPress/WordPress/commit/a2693fd8602e3263b5925b9d799ddd577202167d
- https://lists.debian.org/debian-lts-announce/2017/11/msg00003.html

### 🔴 CVE-2018-20148 — CVSS 9.8 (CRITICAL)
- **Published:** 2018-12-14  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object injection attacks via crafted metadata in a wp.getMediaItem XMLRPC call. This is caused by mishandling of serialized data at phar:// URLs in the wp_get_attachment_thumb_file function in wp-includes/post.php.

**Affected Products (CPE):**
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*`

**References:**
- http://www.securityfocus.com/bid/106220
- https://blog.secarma.co.uk/labs/near-phar-dangerous-unserialization-wherever-you-are
- https://codex.wordpress.org/Version_4.9.9
- https://lists.debian.org/debian-lts-announce/2019/02/msg00019.html
- https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/

### 🔴 CVE-2019-17669 — CVSS 9.8 (CRITICAL)
- **Published:** 2019-10-17  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because URL validation does not consider the interpretation of a name as a series of hex characters.

**Affected Products (CPE):**
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*`

**References:**
- https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
- https://core.trac.wordpress.org/changeset/46475
- https://github.com/WordPress/WordPress/commit/608d39faed63ea212b6c6cdf9fe2bef92e2120ea
- https://lists.debian.org/debian-lts-announce/2019/11/msg00000.html
- https://seclists.org/bugtraq/2020/Jan/8

### 🔴 CVE-2019-17670 — CVSS 9.8 (CRITICAL)
- **Published:** 2019-10-17  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** WordPress before 5.2.4 has a Server Side Request Forgery (SSRF) vulnerability because Windows paths are mishandled during certain validation of relative URLs.

**Affected Products (CPE):**
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*`

**References:**
- https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
- https://core.trac.wordpress.org/changeset/46472
- https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
- https://lists.debian.org/debian-lts-announce/2019/11/msg00000.html
- https://lists.debian.org/debian-lts-announce/2020/09/msg00011.html

### 🔴 CVE-2019-20041 — CVSS 9.8 (CRITICAL)
- **Published:** 2019-12-27  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** wp_kses_bad_protocol in wp-includes/kses.php in WordPress before 5.3.1 mishandles the HTML5 colon named entity, allowing attackers to bypass input sanitization, as demonstrated by the javascript&colon; substring.

**Affected Products (CPE):**
- `cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:8.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*`

**References:**
- https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
- https://lists.debian.org/debian-lts-announce/2020/01/msg00010.html
- https://seclists.org/bugtraq/2020/Jan/8
- https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
- https://www.debian.org/security/2020/dsa-4599

### 🔴 CVE-2026-31789 — CVSS 9.8 (CRITICAL)
- **Published:** 2026-04-07  **Last Modified:** 2026-07-24
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Issue summary: Converting an excessively large OCTET STRING value to
a hexadecimal string leads to a heap buffer overflow on 32 bit platforms.

Impact summary: A heap buffer overflow may lead to a crash or possibly
an attacker controlled code execution or other undefined behavior.

If an attacker can supply a crafted X.509 certificate with an excessively
large OCTET STRING value in extensions such as the Subject Key Identifier
(SKID) or Authority Key Identifier (AKID) which are being converted to hex,
the size of the buffer needed for the result is calculated as multiplication
of the input length by 3. On 32 bit platforms, this multiplication may overflow
resulting in the allocation of a smaller buffer and a heap buffer overflow.

Applications and services that print or log contents of untrusted X.509
certificates are vulnerable to this issue. As the certificates would have
to have sizes of over 1 Gigabyte, printing or logging such certificates
is a fairly unlikely operation and only 32 bit platforms are affected,
this issue was assigned Low severity.

The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this
issue, as the affected code is outside the OpenSSL FIPS module boundary.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/364f095b80601db632b0def6a33316967f863bde
- https://github.com/openssl/openssl/commit/7a9087efd769f362ad9c0e30c7baaa6bbfa65ecf
- https://github.com/openssl/openssl/commit/945b935ac66cc7f1a41f1b849c7c25adb5351f49
- https://github.com/openssl/openssl/commit/a24216018e1ede8ff01a4ff5afff7dfbd443e2f9
- https://github.com/openssl/openssl/commit/a91e537d16d74050dbde50bb0dfb1fe9930f0521

### 🔴 CVE-2020-11984 — CVSS 9.8 (CRITICAL)
- **Published:** 2020-08-07  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_element_manager:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_session_report_manager:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:communications_session_route_manager:*:*:*:*:*:*:*:*`

**References:**
- http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00068.html
- http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00071.html
- http://packetstormsecurity.com/files/159009/Apache2-mod_proxy_uwsgi-Incorrect-Request-Handling.html
- http://www.openwall.com/lists/oss-security/2020/08/08/1
- http://www.openwall.com/lists/oss-security/2020/08/08/10

### 🔴 CVE-2021-26691 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-06-10  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:enterprise_manager_ops_center:12.4.0.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`

**References:**
- http://httpd.apache.org/security/vulnerabilities_24.html
- http://www.openwall.com/lists/oss-security/2021/06/10/7
- https://lists.apache.org/thread.html/r50cae1b71f1e7421069036b213c26da7d8f47dd59874e3bd956959fe%40%3Cannounce.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r7f2b70b621651548f4b6f027552f1dd91705d7111bb5d15cda0a68dd%40%3Cdev.httpd.apache.org%3E
- https://lists.apache.org/thread.html/re026d3da9d7824bd93b9f871c0fdda978d960c7e62d8c43cba8d0bf3%40%3Ccvs.httpd.apache.org%3E

### 🔴 CVE-2021-39275 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-09-16  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache HTTP Server 2.4.48 and earlier.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:clustered_data_ontap:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:storagegrid:-:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:http_server:12.2.1.3.0:*:*:*:*:*:*:*`

**References:**
- https://cert-portal.siemens.com/productcert/pdf/ssa-685781.pdf
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://lists.apache.org/thread.html/r3925e167d5eb1c75def3750c155d753064e1d34a143028bb32910432%40%3Cusers.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r61fdbfc26ab170f4e6492ef3bd5197c20b862ce156e9d5a54d4b899c%40%3Cusers.httpd.apache.org%3E
- https://lists.apache.org/thread.html/r82838efc5fa6fc4c73986399c9b71573589f78b31846aff5bd9b1697%40%3Cusers.httpd.apache.org%3E

### 🔴 CVE-2021-41773 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-10-05  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*`

**References:**
- http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal.html
- http://packetstormsecurity.com/files/164629/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164941/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html
- http://www.openwall.com/lists/oss-security/2021/10/05/2

### 🔴 CVE-2021-42013 — CVSS 9.8 (CRITICAL)
- **Published:** 2021-10-07  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:oracle:instantis_enterprisetrack:17.3:*:*:*:*:*:*:*`

**References:**
- http://jvn.jp/en/jp/JVN51106450/index.html
- http://packetstormsecurity.com/files/164501/Apache-HTTP-Server-2.4.50-Path-Traversal-Code-Execution.html
- http://packetstormsecurity.com/files/164609/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164629/Apache-2.4.49-2.4.50-Traversal-Remote-Code-Execution.html
- http://packetstormsecurity.com/files/164941/Apache-HTTP-Server-2.4.50-Remote-Code-Execution.html

### 🔴 CVE-2016-3088 — CVSS 9.8 (CRITICAL)
- **Published:** 2016-06-01  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*`

**References:**
- http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt
- http://rhn.redhat.com/errata/RHSA-2016-2036.html
- http://www.securitytracker.com/id/1035951
- http://www.zerodayinitiative.com/advisories/ZDI-16-356
- http://www.zerodayinitiative.com/advisories/ZDI-16-357

### 🔴 CVE-2026-34182 — CVSS 9.1 (CRITICAL)
- **Published:** 2026-06-09  **Last Modified:** 2026-07-23
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Description:** Issue Summary: Cryptographic Message Services (CMS) processing fails to perform
sufficient input validation on the cipher and tag length fields of
AuthEnvelopedData containers, leading to various potential compromises.

Impact Summary: Attackers making use of these vulnerabilities may achieve
key-equivalent functionality for a given CMS recipient and/or bypass integrity
validation for a given message.

In one use case, an attacker may send a CMS message containing
AuthEnvelopedData with the cipher specified as a non-AEAD cipher.  OpenSSL
erroneously allows this selection, and attempts to decrypt and validate the
message.

An on-path attacker who captures one legitimate AES-GCM AuthEnvelopedData
addressed to the victim can re-emit it with the recipientInfos set left
byte-for-byte intact, so the victim's private key still unwraps the genuine CEK
(the content-encryption key), but with the inner OID rewritten to AES-256-OFB
(Output Feedback Mode, an unauthenticated keystream mode) and with an
attacker-chosen IV and ciphertext. The victim initializes AES-256-OFB under the
real CEK, never consults the MAC field, and CMS_decrypt() returns success.

If the application under attack responds to the attacker with any indicator
showing success or failure of the decryption effort, it is possible for the
attacker to use this as an oracle to obtain key equivalent functionality for the
CEK used for the chosen recipient of the message.

In another use case, an attacker can reduce the tag length of the chosen AEAD
cipher for a given AuthEnvelopedData container to be a single byte long,
allowing an attacker to brute force CMS decryption, producing an integrity
bypass for applications that trust CMS_decrypt() to reject modified content.

The FIPS modules are not affected by this issue.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:4.0.0:-:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/03c1f4d45fb963aee7d5833390c507cd290182bc
- https://github.com/openssl/openssl/commit/439ed7d2c0962ce964482727264668bf277c333f
- https://github.com/openssl/openssl/commit/7947e6a81eb8776802f159fb6762cb7fcf7e34c7
- https://github.com/openssl/openssl/commit/9fd97f8cfdc2c0be214998de3b2b55c8edf6c7ac
- https://github.com/openssl/openssl/commit/d2ca86bcd43e4f17d899f347101766b6107676e0

### 🟠 CVE-2025-15467 — CVSS 8.8 (HIGH)
- **Published:** 2026-01-27  **Last Modified:** 2026-09-07
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

**Description:** Issue summary: Parsing CMS AuthEnvelopedData or EnvelopedData message with
maliciously crafted AEAD parameters can trigger a stack buffer overflow.

Impact summary: A stack buffer overflow may lead to a crash, causing Denial
of Service, or potentially remote code execution.

When parsing CMS (Auth)EnvelopedData structures that use AEAD ciphers such as
AES-GCM, the IV (Initialization Vector) encoded in the ASN.1 parameters is
copied into a fixed-size stack buffer without verifying that its length fits
the destination. An attacker can supply a crafted CMS message with an
oversized IV, causing a stack-based out-of-bounds write before any
authentication or tag verification occurs.

Applications and services that parse untrusted CMS or PKCS#7 content using
AEAD ciphers (e.g., S/MIME (Auth)EnvelopedData with AES-GCM) are vulnerable.
Because the overflow occurs prior to authentication, no valid key material
is required to trigger it. While exploitability to remote code execution
depends on platform and toolchain mitigations, the stack-based write
primitive represents a severe risk.

The FIPS modules in 3.6, 3.5, 3.4, 3.3 and 3.0 are not affected by this
issue, as the CMS implementation is outside the OpenSSL FIPS module
boundary.

OpenSSL 3.6, 3.5, 3.4, 3.3 and 3.0 are vulnerable to this issue.

OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/2c8f0e5fa9b6ee5508a0349e4572ddb74db5a703
- https://github.com/openssl/openssl/commit/5f26d4202f5b89664c5c3f3c62086276026ba9a9
- https://github.com/openssl/openssl/commit/6ced0fe6b10faa560e410e3ee8d6c82f06c65ea3
- https://github.com/openssl/openssl/commit/ce39170276daec87f55c39dad1f629b56344429e
- https://github.com/openssl/openssl/commit/d0071a0799f20cc8101730145349ed4487c268dc

### 🟠 CVE-2026-45447 — CVSS 8.8 (HIGH)
- **Published:** 2026-06-09  **Last Modified:** 2026-09-11
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

**Description:** Issue summary: A specially crafted PKCS#7 or S/MIME signed message could
trigger a use-after-free during PKCS#7 signature verification.

Impact summary: A use-after-free may result in process crashes, heap
corruption, or potentially remote code execution.

When processing a PKCS#7 or S/MIME signed message, if the SignedData
digestAlgorithms field is present as an empty ASN.1 SET, OpenSSL may
incorrectly free a caller-owned BIO during PKCS7_verify(). A subsequent
use of the BIO by the calling application results in a use-after-free
condition.

In the common case this occurs when the application later calls
BIO_free() on the BIO originally passed to PKCS7_verify(). Depending
on allocator behavior and application-specific BIO usage patterns, this
may result in a crash or other memory corruption. In some application
contexts this may potentially be exploitable for remote code execution.

Applications that process PKCS#7 or S/MIME signed messages using OpenSSL
PKCS#7 APIs may be affected. Applications using the CMS APIs for this
processing are not affected.

The FIPS modules in 4.0, 3.6, 3.5, 3.4, and 3.0 are not affected by this
issue, as the affected code is outside the OpenSSL FIPS module boundary.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/3aad5eb7af4de4ee0633c30a8541a54d9bbde63c
- https://github.com/openssl/openssl/commit/7d4a980c62258c5910cc883936e0c8dbab4d75a8
- https://github.com/openssl/openssl/commit/9dfd688ad2290fc5075cacbc9bf0c9a93eefed54
- https://github.com/openssl/openssl/commit/a541ae8bfe849a30cc885e8780715c0f488e496c
- https://github.com/openssl/openssl/commit/c505d7559da5d5f9f2c3913c6883a5562ce7273e

### 🟠 CVE-2026-28387 — CVSS 8.1 (HIGH)
- **Published:** 2026-04-07  **Last Modified:** 2026-07-24
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Issue summary: An uncommon configuration of clients performing DANE TLSA-based
server authentication, when paired with uncommon server DANE TLSA records, may
result in a use-after-free and/or double-free on the client side.

Impact summary: A use after free can have a range of potential consequences
such as the corruption of valid data, crashes or execution of arbitrary code.

However, the issue only affects clients that make use of TLSA records with both
the PKIX-TA(0/PKIX-EE(1) certificate usages and the DANE-TA(2) certificate
usage.

By far the most common deployment of DANE is in SMTP MTAs for which RFC7672
recommends that clients treat as 'unusable' any TLSA records that have the PKIX
certificate usages.  These SMTP (or other similar) clients are not vulnerable
to this issue.  Conversely, any clients that support only the PKIX usages, and
ignore the DANE-TA(2) usage are also not vulnerable.

The client would also need to be communicating with a server that publishes a
TLSA RRset with both types of TLSA records.

No FIPS modules are affected by this issue, the problem code is outside the
FIPS module boundary.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/07e727d304746edb49a98ee8f6ab00256e1f012b
- https://github.com/openssl/openssl/commit/258a8f63b26995ba357f4326da00e19e29c6acbe
- https://github.com/openssl/openssl/commit/444958deaf450aea819171f97ae69eaedede42c3
- https://github.com/openssl/openssl/commit/7a4e08cee62a728d32e60b0de89e6764339df0a7
- https://github.com/openssl/openssl/commit/ec03fa050b3346997ed9c5fef3d0e16ad7db8177

### 🟠 CVE-1999-0045 — CVSS 7.5 (HIGH)
- **Published:** 1996-12-10  **Last Modified:** 2026-06-16
- **Vector:** `AV:N/AC:L/Au:N/C:P/I:P/A:P`

**Description:** List of arbitrary files on Web host via nph-test-cgi script.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:0.8.11:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:0.8.14:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0.3:*:*:*:*:*:*:*`

**References:**
- https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0045
- https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0045

### 🟡 CVE-1999-0070 — CVSS 5.0 (MEDIUM)
- **Published:** 1996-04-01  **Last Modified:** 2026-06-16
- **Vector:** `AV:N/AC:L/Au:N/C:N/I:P/A:N`

**Description:** test-cgi program allows an attacker to list files on the server.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`

**References:**
- https://lists.apache.org/thread.html/rc5d27fc1e76dc5650e1a3f1db1de403120f4c2d041cb7352850455c2%40%3Cusers.httpd.apache.org%3E
- https://lists.apache.org/thread.html/rc5d27fc1e76dc5650e1a3f1db1de403120f4c2d041cb7352850455c2%40%3Cusers.httpd.apache.org%3E

### 🟡 CVE-1999-0925 — CVSS 5.0 (MEDIUM)
- **Published:** 1999-09-03  **Last Modified:** 2026-06-16
- **Vector:** `AV:N/AC:L/Au:N/C:N/I:N/A:P`

**Description:** UnityMail allows remote attackers to conduct a denial of service via a large number of MIME headers.

**Affected Products (CPE):**
- `cpe:2.3:a:messagemedia:unitymail:*:*:*:*:*:*:*:*`

**References:**
- http://marc.info/?l=bugtraq&m=90486243124867&w=2
- http://marc.info/?l=bugtraq&m=90486243124867&w=2

### 🟡 CVE-1999-0107 — CVSS 5.0 (MEDIUM)
- **Published:** 1997-12-30  **Last Modified:** 2026-06-16
- **Vector:** `AV:N/AC:L/Au:N/C:N/I:N/A:P`

**Description:** Buffer overflow in Apache 1.2.5 and earlier allows a remote attacker to cause a denial of service with a large number of GET requests containing a large number of / characters.

**Affected Products (CPE):**
- `cpe:2.3:a:apache:http_server:0.8.11:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:0.8.14:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:apache:http_server:1.0.3:*:*:*:*:*:*:*`

**References:**
- https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0107
- https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0107


*(1 weitere produkt-generische CVE(s) ohne Versions-Match wurden als nicht-verwertbar ausgeblendet.)*
