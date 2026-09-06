# PhishGuard — Advanced Android Phishing & Threat Detection Engine

PhishGuard is a privacy-conscious Android application engineered to inspect, dissect, and score phishing attempts, deceptive URL structures, brand impersonation attacks, and social engineering messages. Built with **Jetpack Compose**, **Material 3**, and **Nothing OS-inspired typography & 120Hz spring physics**, PhishGuard fuses local offline intelligence with optional cloud-augmented reasoning.

---

## ⚡ Architecture & Multi-Tiered Detection Pipeline

PhishGuard employs a layered defense-in-depth pipeline where local deterministic heuristics, statistical ML, and retrieval-augmented reasoning collaborate to evaluate target URLs and accompanying messages.

```
Incoming URL + Message Context
        │
        ├──► Layer 1: Supervised ML Classifier (24 Lexical & Structural Features)
        ├──► Layer 2: Zero-Trust URL Structure & Path Lexical Analyzer
        ├──► Layer 3: Brand Impersonation & Spoofing Radar
        ├──► Layer 4: Statistical + Rule-Based Semantic NLP Urgency Engine
        ├──► Layer 5: Local Threat Knowledge Base & Signatures
        ├──► Layer 6: TF-IDF Cosine Similarity Threat RAG (Top-K Retrieval)
        └──► Layer 7: SQLite Room Registry (RBI .bank.in & Whitelist Cross-Check)
        │
        ▼
   [Local Multi-Tier Synthesis Engine] ──► (Offline Verdict & Telemetry)
        │
        ▼ (If Gemini API Key Available)
   [Gemini Neural Reasoning Layer] ──► (Evidence-Grounded Explanation)
        │
        ▼
   [Deterministic Safety Override] ──► Final Risk Score & Status
```

---

## 🔍 Core Subsystems

### 1. Supervised Machine Learning Classifier
- **Model Architecture**: Supervised Logistic Regression classifier with L2 regularization ($\lambda = 0.01$) operating on a 24-dimensional normalized feature space.
- **Feature Vector**:
  - *Structural*: `urlLength`, `hostLength`, `pathLength`, `queryLength`, `slashCount`, `dotCount`, `hyphenCount`, `equalCount`, `questionMarkCount`, `atSymbolCount`, `ampersandCount`, `subdomainCount`, `hasCustomPort`, `isHttps`, `isIpAddress`.
  - *Information-Theoretic*: Shannon entropy of host domain, Shannon entropy of URL path.
  - *Lexical & Tokens*: `digitCount`, `hostDigitCount`, `digitRatio`, `tldAbuseRisk`, `phishingKeywordCount`, `tokenCount`, `longestTokenLength`.
- **Dataset & Provenance**:
  - Curated corpus of 187 URLs: 99 verified legitimate domains and 88 verified phishing/scam URLs representing banking, postal, crypto, government, and brand spoofing vectors.
  - **Domain-Grouped Stratified Partition**: Grouped strictly by registrable domain with a fixed random seed (`42`) to prevent data leakage.
  - **Partitions**:
    - Training Set: 131 URLs (69 legit, 62 phish) — 70.1%
    - Validation Set: 28 URLs (15 legit, 13 phish) — 15.0%
    - Held-Out Test Set: 28 URLs (15 legit, 13 phish) — 15.0%
  - **Strict Leakage Prevention**: Normalization statistics (feature means and standard deviations) were calculated solely on the 70% training split. Hyperparameters and decision threshold (0.50) were chosen on the validation split. The held-out test split was evaluated exactly once. Zero URL or registrable-domain overlap exists between splits.
- **Evaluation Metrics**:
  - *Held-Out Test Set (28 samples)*: Accuracy 100.00% (15 TN, 0 FP, 13 TP, 0 FN), Precision 1.0000, Recall 1.0000, F1 1.0000, ROC-AUC 1.0000.
  - *External Sanity Check (40 unseen URLs — 20 legit, 20 phish)*: 100.00% Phishing Detection Rate (20/20, 0 FN), 100.00% Legitimate Retention Rate (20/20, 0 FP).
  - *Note on Performance Claims*: These results reflect evaluation on the curated benchmark test distributions. They do not constitute an absolute claim of 100% detection against unconstrained, mutating zero-day wild internet distributions, which is why PhishGuard couples the model with deterministic structural and brand heuristics.
- **Artifact Synchronization**: Model version `v1.1.0-stratified` (Checksum `4cdf75ebeca34bf0`). Learned weights, bias, feature means, and standard deviations are exported by `scripts/train_classifier.py` to `trained_model.json`, packaged into `app/src/main/assets/`, and compiled directly into `SupervisedUrlClassifier.kt`.

### 2. Zero-Trust URL Structure & Path Analysis
- Dissects full URL endpoints down to path tokens and query parameters.
- **Path Tampering & Obfuscation**: Flags character substitution/leetspeak in sensitive endpoints (e.g., `/l0gin`, `/s1gnin`, `/ver1fy`, `/p4ssword`).
- **Open Redirect Detection**: Identifies parameters (`url=`, `redirect=`, `next=`, `dest=`) pointing to third-party endpoints.
- **Dangerous Payloads**: Detects executable file extensions in paths (`.apk`, `.exe`, `.bat`, `.scr`).
- **Identity Tricks**: Flags `@` symbol URL authority confusion, raw IP hosts, punycode/IDN homograph representations, and high-risk TLDs (`.top`, `.xyz`, `.buzz`, `.icu`, `.cfd`).

### 3. Brand Impersonation & Authority Radar
- Evaluates domain tokens against high-value target profiles (banking institutions, tech ecosystems, postal logistics, government portals).
- Flags brand keyword stuffing on unauthorized hosts (e.g. `sbi-kyc-update.xyz`, `inddiapost-tracking.top`).
- Respects officially accredited domain boundaries (e.g. RBI-restricted `.bank.in` registry, `.gov.in`, `.sbi`, `.apple.com`).

### 4. Statistical + Rule-Based Semantic NLP
- Analyzes message context (SMS, email, messaging lures) using statistical linguistic metrics and deterministic keyword matchers.
- **Linguistic Metrics**: Calculates imperative command ratios (frequency of directive imperative verbs), lexical diversity (type-token ratio), and Shannon text entropy.
- **Homoglyph & De-obfuscation**: Strips zero-width unicode spaces (`\u200B`, `\uFEFF`) and normalizes Cyrillic/Greek homoglyphs (e.g. Cyrillic 'а' replacing Latin 'a').
- **Coercion Vectors**: Categorizes temporal deadlines (24h freeze, expiry), punitive consequences (account suspension, legal action), credential harvesting (OTP, PIN, seed phrase requests), and greed bait (tax refund, reward points).
- *Implementation Classification*: This component is explicitly rule-based and statistical NLP; it does not rely on a heavy transformer or deep learning NLP runtime.

### 5. TF-IDF Cosine Similarity Threat RAG
- **Vector Space Retrieval**: Indexes structured threat dossiers covering active phishing campaigns across banking, logistics, crypto, and scareware categories.
- Computes query term frequencies and TF-IDF representations from input URLs and message context.
- Measures cosine similarity against indexed threat campaigns, returning top-K matches with similarity coefficients and matched Indicators of Compromise (IOCs).
- Injects concrete retrieved threat telemetry into downstream reasoning layers.

### 6. Local Threat Knowledge Base
- Maintained in `ThreatDatabase.kt` and SQLite Room `ThreatIntelDao`.
- Stores curated threat campaigns, known phishing domains, indicators of compromise, and attack vectors.
- Matches incoming URLs and host tokens against local heuristic signatures.
- *Classification*: Serves as a local offline threat intelligence repository, not a real-time internet-wide streaming feed.

### 7. Gemini Neural Reasoning & Deterministic Safety Override
- Uses Google Gemini (`gemini-2.5-flash`) via `GeminiApiService` to generate human-readable technical explanations and synthesize cross-vector insights.
- **Evidence-Grounded Prompting**: Gemini is fed the raw, genuine outputs of all local analyzers (URL analysis, ML probability and top contributors, NLP coercion metrics, RAG campaign matches, and whitelist status). The system instruction strictly prohibits inventing external breach claims.
- **Deterministic Override Enforcement**: Gemini cannot overturn deterministic local security findings. If local engines detect verified brand impersonation, path leetspeak tampering, open redirects, executable payloads, or critical threat signatures, the final risk score is enforced at or above the local baseline ($\ge 65$), and a safety override notice is appended.
- **Resilient Fallback**: If the Gemini API key is absent or network fails, the local synthesis engine provides complete, offline risk scoring and explanations without disruption.

### 8. SQLite Room Persistence & Whitelist Registry
- Backed by Room Database with KSP (`phish_shield_db`).
- Entities: `ScanHistoryEntity`, `WhitelistEntity`, `ThreatIntelEntity`.
- Pre-populated with official banking authorities (RBI `.bank.in` ecosystem, SEBI, UIDAI, Income Tax) and known threat catalogs.
- **Whitelist Security Rule**: Matching the whitelist does **not** grant blanket immunity. If an attacker leverages path tampering (e.g., `/l0gin`), open redirects, or executable payloads, the whitelist match is superseded and the threat is surfaced.

---

## 📊 Dataset & Model Provenance Summary

| Category | Description | Count |
| :--- | :--- | :--- |
| **Total Dataset** | Curated balance of legitimate web portals and verified phishing lures | 187 URLs |
| **Legitimate URLs** | Global Alexa/Tranco top sites, banking portals, developer resources | 99 URLs (52.9%) |
| **Phishing URLs** | Active phishing kits, credential harvesting pages, smishing campaigns | 88 URLs (47.1%) |
| **Training Split** | 70.1% domain-grouped stratified split (means/stds computed here) | 131 URLs |
| **Validation Split** | 15.0% domain-grouped stratified split (threshold tuning = 0.50) | 28 URLs |
| **Held-Out Test Split** | 15.0% domain-grouped held-out test split (evaluated once) | 28 URLs |
| **External Sanity Check** | Distinct unseen domains (20 legitimate, 20 phishing) | 40 URLs |

*Provenance Note*: Legitimate URLs originate from verified public sector and institutional portals. Phishing patterns reflect active campaigns reported across CERT-In advisories, PhishTank corpora, and OpenPhish signatures.

---

## 🛡️ Limitations

1. **Dataset Scope**: The supervised ML model is trained on a curated corpus of 187 URLs with 24 engineered features. While achieving high accuracy on the evaluation and sanity sets, novel zero-day attack topologies that evade these 24 features rely on PhishGuard's downstream brand and structural heuristics.
2. **Language Coverage**: Statistical NLP heuristics are currently tuned for English-language social engineering and smishing message templates.
3. **Local Knowledge Base**: The threat intelligence database operates locally offline; it is updated via app revisions or custom user IOC additions rather than a live external subscriber feed.
4. **Network Dependencies**: Advanced AI reasoning requires network connectivity to the Gemini API and a valid API key configured in AI Studio Secrets (`GEMINI_API_KEY`). Full offline detection is available locally at all times.

---

## 🛠️ Tech Stack

- **Platform**: Android (minSdk 26, targetSdk 36)
- **Language**: Kotlin 2.0.21
- **UI Framework**: Jetpack Compose, Material Design 3
- **Local Persistence**: Room Database 2.6.1 with KSP
- **Networking & Serialization**: Retrofit 2.11.0, OkHttp 4.12.0, Moshi 1.15.2
- **Testing**: JUnit 4, Robolectric (SDK 36)
- **Secrets Management**: Secrets Gradle Plugin (.env / BuildConfig)

