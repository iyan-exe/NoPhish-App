# Security Implementation Plan: NoPhish Hardening & Typosquatting Defense

## Security Threat Model

### Component Overview
The NoPhish application is an Android cyber-defense client evaluating URLs for phishing, credential harvesting, brand impersonation, and social engineering attacks. Consumers include mobile device users submitting URLs manually or via Android sharesheet intents. Execution happens entirely on-device (local heuristic/feature extraction, Room database, RAG vector retrieval, and supervised ML inference), with optional cloud neural reasoning via Gemini.

### Entry Points and Untrusted Inputs
| Entry Point | Type | Trusted? | Validation |
|---|---|---|---|
| User URL Input Field | UI Text Input | No (Untrusted) | Normalized with scheme prefix, parsed via URI |
| Message Context Input | UI Text Input | No (Untrusted) | NLP text tokenization |
| Whitelist / Threat DB | Room SQLite DB | Yes (Internal) | Pre-populated verified banking and authority domains |

### Trust Boundaries and Auth Assumptions
- **Client-Side Decision Integrity**: The app must defend users against deceptive attacker URLs. Trusting a parent domain (e.g. `*.sbi`, `*.bank.in`) without verifying the complete subdomain structure allows malicious or spoofed subdomains to bypass defenses.
- **Whitelist Boundary**: Whitelisting a root domain (e.g. `onlinesbi.sbi`) must only bless verified official hostnames or clean/standard subdomains, never lookalike or typosquatted subdomains.

### Sensitive Data Paths
| Data Type | Source | Destination | Protection |
|---|---|---|---|
| Target URL | End-User Input | Feature Extractor & Threat Evaluator | Sanitized URI parsing, domain boundary separation |
| Threat Verdict | Engine Evaluator | Room Scan History & UI | Structured data model, deterministic override |

### Privileged Actions
| Action | Location | Guard |
|---|---|---|
| URL Classification / Overrides | `PhishingDetectorEngine.kt` | Multi-signal corroboration & deterministic override |
| Whitelist Domain Matching | `PhishingDetectorEngine.kt`, `DomainUtils.kt` | Strict subdomain boundary validation |

### Priority Review Areas
1. **Subdomain Lookalike Detection**: `DomainUtils.kt`, `UrlStructureAnalyzer.kt`, `BrandImpersonationDetector.kt` to catch `retaii`, `retial`, `retaiI`, `retai1`, `retall` mimicking `retail`.
2. **Whitelist Boundary Guard**: Preventing `isKnownLegitimate` or root-domain whitelist match from conferring blanket immunity when a suspicious subdomain is present.
3. **Multi-Signal Corroboration & Deterministic Override**: Upgrading verdict to `Phishing` when subdomain lookalike, path typo, and sensitive login context co-occur.

---

## Proposed Changes

### 1. Robust Subdomain & Hostname Breakdown (`DomainUtils.kt` & `UrlStructureAnalyzer.kt`)
- Extract `subdomain`, `registrableDomain`, `domainName`, `publicSuffix` using exact boundaries.
- Update `isIndianBankingDomain` and `isKnownTopLegitimateDomain` to require exact official hostname matching or strict clean-subdomain validation. Do NOT treat `clean.endsWith(".sbi")` as an automatic pass if the subdomain is a lookalike/typosquat.
- Maintain structured official SBI hostnames (`retail.onlinesbi.sbi`, `onlinesbi.sbi`, `sbi.co.in`, etc.).

### 2. Comprehensive Typosquatting & Lookalike Engine (`TyposquattingDetector.kt` / `UrlStructureAnalyzer.kt`)
- Detect character insertions, deletions, substitutions, adjacent transpositions, repeated padding, visual homoglyphs (`i` vs `l`, `ii` vs `il`, `1` vs `l`, uppercase `I` vs `l`), and digit/leetspeak substitutions.
- Compare subdomains and path tokens against high-value brand and service keywords:
  - Banking/Service labels: `retail`, `corporate`, `netbanking`, `banking`, `personal`, `login`, `signin`, `auth`, `account`, `portal`, `secure`, `verify`.
  - Brand names: `sbi`, `onlinesbi`, `hdfc`, `icici`, `paypal`, `google`, `microsoft`, `apple`, `amazon`, etc.

### 3. Subdomain Impersonation in `BrandImpersonationDetector.kt`
- Evaluate subdomains for lookalikes of official service identifiers (e.g. `retaii` imitating `retail`).
- If an untrusted or lookalike subdomain mimics a legitimate brand service, flag as `isImpersonating = true` with high/critical severity.

### 4. Whitelist & Trusted-Domain Logic Hardening in `PhishingDetectorEngine.kt`
- If a root domain is whitelisted, check whether the subdomain is a lookalike/typosquat or contains phishing indicators.
- If subdomain tampering or path lookalikes with login context are detected, revoke whitelist immunity.
- Implement deterministic security override: when lookalike subdomain + path typo + login context corroborate, verdict must be `Phishing` with score $\ge 75$.

---

## Verification Plan

### Security Verification
- **Security Scan**: Inspect all newly created and modified files for common CWE vulnerabilities (XSS, injection, exposed secrets, missing auth boundaries). Resolve any detected issues immediately.
- **Security Audit**: Audit the implementation against the component's threat model (`## Security Threat Model`). Document all findings, dispositions, and remediations in `walkthrough.md` using the `generate-security-audit-report` skill.
- **PoC Verification**: Validate using `run-poc` that `https://retaii.onlinesbi.sbi/retial/login.html` is strictly blocked and reported as `Phishing`.

### Test Cases
- `https://retaii.onlinesbi.sbi/retial/login.html` -> `Phishing` (Score $\ge 75$)
- `https://retial.onlinesbi.sbi/retail/login.html` -> `Phishing`
- `https://retaiI.onlinesbi.sbi/retail/login.html` -> `Phishing`
- `https://retai1.onlinesbi.sbi/retail/login.html` -> `Phishing`
- `https://retail.onlinesbi.sbi/retail/login.html` -> `Safe` (Score 0)
- `https://retail.onlinesbi.sbi/retial/login.html` -> `Suspicious` (Score 35)
- Legitimate global domains (`github.com/login`, `google.com`, `wikipedia.org`) -> `Safe`
