# 🛡️ Rust Guardrail — High-Performance AI Safety & Security Proxy

**Rust Guardrail** is a high-performance, low-latency AI safety and privacy proxy layer positioned between client applications and Large Language Model (LLM) APIs (such as Google Gemini API).

The project safeguards LLM-powered applications against common security vulnerabilities (Prompt Injections, PII/data leaks, malicious URLs) while maintaining near-zero latency overhead and zero extra token cost for pre-filtering, leveraging Rust's native speed and memory safety.

---

## 🚀 Key Features

* **🛡️ Input Guardrail (Prompt Injection Protection):** Detects and blocks attempts to manipulate the model or bypass system instructions (e.g., *jailbreak*, *ignore previous instructions* patterns).
* **🔒 PII Redactor Tool (Data Privacy & GDPR):** Automatically scans and redacts sensitive personal data (e.g., email addresses, credit card numbers, Hungarian TAJ/SSN IDs) with `[REDACTED]` tokens before sending prompts to the LLM.
* **🌐 Threat Intelligence Tool (VirusTotal API Integration):** Parses URLs and IP addresses contained in incoming prompts and queries the VirusTotal API asynchronously to verify their safety score.
* **🐥 Output Canary Guard:** Injects unique canary tokens into the system context to prevent internal prompts or secret values from leaking in model responses.
* **📊 Automated Incident Audit Skill:** Automatically generates structured Incident Audit Reports (in JSON/Markdown format) whenever a security breach or injection attempt is intercepted.

---

## 🏗️ System Architecture

```text
[ Client / User ]
        │
        ▼ (HTTP POST /v1/chat)
┌────────────────────────────────────────────────────────┐
│                RUST GUARDRAIL PROXY                    │
│                                                        │
│  1. Input Guard       ──► Prompt Injection Filter      │
│  2. PII Redactor      ──► TAJ, Email, Card Redaction   │
│  3. Threat Intel Tool ──► VirusTotal API Lookup        │
└───────────────────────────┬────────────────────────────┘
                            │ (Sanitized & Redacted Prompt)
                            ▼
┌────────────────────────────────────────────────────────┐
│               LLM PROVIDER (Gemini API)                │
└───────────────────────────┬────────────────────────────┘
                            │ (Raw Model Response)
                            ▼
┌────────────────────────────────────────────────────────┐
│  4. Output Guard      ──► Canary Token & Leak Filter   │
│  5. Audit Skill       ──► Incident Logging & Report    │
└───────────────────────────┬────────────────────────────┘
                            │ (Safe Response / Audit Log)
                            ▼
                 [ Client / User ]
```

Redactor test run:
<img width="1630" height="141" alt="image" src="https://github.com/user-attachments/assets/78157264-4d50-4317-8ff5-c0122c26927d" />
