PhishGuard is a modern Android application engineered to detect, dissect, and neutralize sophisticated phishing attempts, deceptive URL paths, brand impersonation attacks, and social engineering messages in real time.

Built with **Jetpack Compose**, **Material 3**, and **Nothing OS-inspired typography & 120Hz physics**, PhishGuard combines local offline heuristics with cloud-augmented intelligence for multi-tiered protection.

---

## ⚡ Key Features

### 🔍 Multi-Tiered Detection Pipeline
- **Zero-Trust Structural & Path Inspection**: Evaluates full URLs down to the endpoint path. Detects leetspeak obfuscations (e.g., `/l0gin`), path traversal, open redirects, and direct payload distributions (`.apk`, `.exe`).
- **Brand & Domain Impersonation Engine**: Identifies typosquatting, bit-squatting, IDN Homoglyph attacks (punycode spoofing), and unofficial subdomains masquerading as trusted institutions (banks, tech giants, government portals).
- **NLP Social Engineering Analysis**: Scans accompanying SMS/email text for psychological triggers (artificial urgency, panic creation, credential/OTP demands, fake reward hooks).
- **RALM (Retrieval-Augmented LLM) Analysis**: Leverages Google Gemini models augmented with real-time threat intelligence for zero-day phishing classification and technical breakdown.

### 🎨 Design & Experience
- **Nothing OS Minimalist Aesthetic**: Dot-matrix canvas elements, monochrome high-contrast dials, and refined status badging.
- **Fluid 120Hz Animations**: Directional spring-physics tab navigation and real-time live URL dissection as you type or paste.
- **Offline-First Resilience**: Room Database integration for local threat intelligence whitelisting, history audits, and offline risk scoring.

---

## 🛠️ Tech Stack & Architecture

- **Language**: Kotlin
- **UI Toolkit**: Jetpack Compose, Material Design 3
- **Architecture**: Clean Architecture / MVVM
- **Local Persistence**: Room Database (KSP)
- **AI / Cloud Intelligence**: Gemini API (RALM Engine)
- **Concurrency & Reactivity**: Kotlin Coroutines & StateFlow
- **Testing**: Robolectric, Roborazzi
