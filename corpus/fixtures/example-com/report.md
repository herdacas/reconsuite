**Target:** example.com  
**Date:** 2026-09-12 04:09  
**Source:** AgentScanIT scan + NVD API v2

---

# Final Report: example.com
## Reconnaissance Summary
  Domain: example.com
  Open ports: 2052,2053,2082,2083,2086,2087,2095,2096,80,443,8080,8443

## Scope & Methodik
| Tool | Zweck | Abgedeckte Assets |
|------|-------|-------------------|
| ddg_search | Domain enumeration via search engine | Domain enumeration |
| httpx | HTTP probing | HTTP/HTTPS endpoint discovery |
| nikto | Web vulnerability scanning | Known vulnerable components |
| nmap | Port scanning | All listed open ports |
| nvd_cpe_lookup | CPE version detection | Service version fingerprinting |
| searchsploit | CVE lookup | Vulnerability research |
| sslscan | TLS service analysis | TLS version and cipher suites |
| subfinder | Subdomain enumeration | Subdomain discovery |
| whatweb | Technology fingerprinting | Web server stack identification |
| whois | Domain registration info | WHOIS data retrieval |

## Confirmed Findings
| Service | Port | Beobachtung | Tool | Trace-Seq# |
|-------|------|-------------|------|----------|
| tcp | 2052 | open | nmap | 1 |
| tcp | 2053 | open | nmap | 2 |
| tcp | 2082 | open | nmap | 3 |
| tcp | 2083 | open | nmap | 4 |
| tcp | 2086 | open | nmap | 5 |
| tcp | 2087 | open | nmap | 6 |
| tcp | 2095 | open | nmap | 7 |
| tcp | 2096 | open | nmap | 8 |
| tcp | 80 | open | nmap | 9 |
| tcp | 443 | open | nmap | 10 |
| tcp | 8080 | open | nmap | 11 |
| tcp | 8443 | open | nmap | 12 |
| tcp | 443 | OpenSSL 3.0.13 detected | sslscan | 13 |

## Detected Technologies
sslscan → OpenSSL 3.0.13

## CVE Validation (NVD API v2)

*Source: https://nvd.nist.gov — 2026-09-12 04:09*

- Gelistet: **8**  Critical: **3**  High: **5**  ·  2 versionslose generische CVE(s) ausgeblendet

### ✅ Versions-verifizierte CVEs

*Service-Version im Scan erkannt und passt zum betroffenen Produkt.*

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

### 🔴 CVE-2026-75803 — CVSS 9.1 (CRITICAL)
- **Published:** 2026-08-25  **Last Modified:** 2026-09-11
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Description:** Issue summary: ChaCha20-Poly1305 and AES-OCB decryption with an empty
ciphertext can report success without verifying the supplied authentication
tag when the operation is finalized by calling the EVP_Cipher() function.

Impact summary: Applications calling EVP_Cipher() on an empty ciphertext and
expecting the call to check the AEAD tag may accept forged messages.

CWE: CWE-354 (Improper Validation of Integrity Check Value)

Description: The EVP_Cipher() API call for AEAD ciphers behaves like a one
shot encryption and decryption call. It also verifies the AEAD tag after the
decryption operation. However for AES-OCB and ChaCha20-Poly1305 ciphers
it skipped the AEAD tag verification when an empty ciphertext was passed to
the function. The callers of this function might believe that a successful
return indicates a valid AEAD tag for these ciphers, even when that has not
truly been validated in this case.

FIPS impact: no
The FIPS modules in 4.0, 3.6, 3.5, 3.4, and 3.0 are not affected by this CVE
as the affected algorithms are not FIPS approved and thus not implemented
in the FIPS module.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/119ab9555dc62275bbd71f6f49529b1a44feba42
- https://github.com/openssl/openssl/commit/3621257986e27e540bf96a11570929a6e5a9e05b
- https://github.com/openssl/openssl/commit/6c7aa6f8f6449b7fe0137ee8be65fcd239bd7d6a
- https://github.com/openssl/openssl/commit/bdeb0cd994d915342787f117ee75044f0dc36f34
- https://github.com/openssl/openssl/commit/bf95f5f772e9362f87b25cfa2f8cb15d984865b9

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

### 🟠 CVE-2026-7383 — CVSS 8.1 (HIGH)
- **Published:** 2026-06-09  **Last Modified:** 2026-07-23
- **Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:** Issue summary: A signed integer overflow when sizing the destination
buffer for Unicode output in ASN1_mbstring_ncopy() can lead to a heap
buffer overflow.

Impact summary: A heap buffer overflow may lead to a crash or possibly
attacker controlled code execution or other undefined behaviour.

In ASN1_mbstring_copy() and ASN1_mbstring_ncopy() the destination
size for Unicode output is computed in a signed int: by left shift
of the input character count for BMPSTRING (UTF-16) and
UNIVERSALSTRING (UTF-32), and by summing per-character byte counts
for UTF8STRING. The calculation overflows when the input reaches
around 2^30 characters. In the worst case (UNIVERSALSTRING at 2^30
characters) the size wraps to zero, OPENSSL_malloc(1) is called, and
the subsequent character copy writes several gigabytes past the
one-byte allocation.

X.509 certificate processing routes through ASN1_STRING_set_by_NID(),
whose DIRSTRING_TYPE mask excludes UNIVERSALSTRING and whose per-NID
size limits cap the input length; no network protocol or
certificate-handling path in OpenSSL exercises the overflow.
Triggering the bug requires an application that calls
ASN1_mbstring_copy() or ASN1_mbstring_ncopy() directly, or registers
a custom string type via ASN1_STRING_TABLE_add(), with
attacker-controlled input on the order of half a gigabyte or more.
For these reasons this issue was assigned Low severity.

The FIPS modules in 4.0, 3.6, 3.5, 3.4 and 3.0 are not affected by
this issue, as the affected code is outside the OpenSSL FIPS module
boundary.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/4f8d2bddaa2c8e06f9c33390ee1717059a6e4be6
- https://github.com/openssl/openssl/commit/80c15faaf78042bbb8654a0e234c50c381732f74
- https://github.com/openssl/openssl/commit/bd17511070fb39a67bfa19682affb765e706a974
- https://github.com/openssl/openssl/commit/c332adaced43bcbb85f97410597e951c11ec3083
- https://github.com/openssl/openssl/commit/d32350ae8ef7426718f5aa9e383d4b51398ee255

### 🟠 CVE-2024-6119 — CVSS 7.5 (HIGH)
- **Published:** 2024-09-03  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Description:** Issue summary: Applications performing certificate name checks (e.g., TLS
clients checking server certificates) may attempt to read an invalid memory
address resulting in abnormal termination of the application process.

Impact summary: Abnormal termination of an application can a cause a denial of
service.

Applications performing certificate name checks (e.g., TLS clients checking
server certificates) may attempt to read an invalid memory address when
comparing the expected name with an `otherName` subject alternative name of an
X.509 certificate. This may result in an exception that terminates the
application program.

Note that basic certificate chain validation (signatures, dates, ...) is not
affected, the denial of service can occur only when the application also
specifies an expected DNS name, Email address or IP address.

TLS servers rarely solicit client certificates, and even when they do, they
generally don't perform a name check against a reference identifier (expected
identity), but rather extract the presented identity after checking the
certificate chain.  So TLS servers are generally not affected and the severity
of the issue is Moderate.

The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:vmware_vsphere:*:*`

**References:**
- https://github.com/openssl/openssl/commit/05f360d9e849a1b277db628f1f13083a7f8dd04f
- https://github.com/openssl/openssl/commit/06d1dc3fa96a2ba5a3e22735a033012aadc9f0d6
- https://github.com/openssl/openssl/commit/621f3729831b05ee828a3203eddb621d014ff2b2
- https://github.com/openssl/openssl/commit/7dfcee2cd2a63b2c64b9b4b0850be64cb695b0a0
- https://openssl-library.org/news/secadv/20240903.txt

### 🟠 CVE-2025-69420 — CVSS 7.5 (HIGH)
- **Published:** 2026-01-27  **Last Modified:** 2026-06-17
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Description:** Issue summary: A type confusion vulnerability exists in the TimeStamp Response
verification code where an ASN1_TYPE union member is accessed without first
validating the type, causing an invalid or NULL pointer dereference when
processing a malformed TimeStamp Response file.

Impact summary: An application calling TS_RESP_verify_response() with a
malformed TimeStamp Response can be caused to dereference an invalid or
NULL pointer when reading, resulting in a Denial of Service.

The functions ossl_ess_get_signing_cert() and ossl_ess_get_signing_cert_v2()
access the signing cert attribute value without validating its type.
When the type is not V_ASN1_SEQUENCE, this results in accessing invalid memory
through the ASN1_TYPE union, causing a crash.

Exploiting this vulnerability requires an attacker to provide a malformed
TimeStamp Response to an application that verifies timestamp responses. The
TimeStamp protocol (RFC 3161) is not widely used and the impact of the
exploit is just a Denial of Service. For these reasons the issue was
assessed as Low severity.

The FIPS modules in 3.5, 3.4, 3.3 and 3.0 are not affected by this issue,
as the TimeStamp Response implementation is outside the OpenSSL FIPS module
boundary.

OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0 and 1.1.1 are vulnerable to this issue.

OpenSSL 1.0.2 is not affected by this issue.

**Affected Products (CPE):**
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*`

**References:**
- https://github.com/openssl/openssl/commit/27c7012c91cc986a598d7540f3079dfde2416eb9
- https://github.com/openssl/openssl/commit/4e254b48ad93cc092be3dd62d97015f33f73133a
- https://github.com/openssl/openssl/commit/564fd9c73787f25693bf9e75faf7bf6bb1305d4e
- https://github.com/openssl/openssl/commit/5eb0770ffcf11b785cf374ff3c19196245e54f1b
- https://github.com/openssl/openssl/commit/a99349ebfc519999edc50620abe24d599b9eb085


*(2 weitere produkt-generische CVE(s) ohne Versions-Match wurden als nicht-verwertbar ausgeblendet.)*
