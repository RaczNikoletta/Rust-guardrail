# Rust Guardrail: AI Safety & Privacy Proxy

**Rust Guardrail** is a small proxy written in Rust (axum) that sits between a client application and a Large Language Model (LLM) API such as Google Gemini. It checks every prompt **before** it reaches the model.

It uses deterministic checks only (regex, checksums and an API lookup). This makes it cheap (no extra LLM calls for guarding), predictable and easy to unit test. It is a university project and a first line of defense, not a replacement for full frameworks such as NVIDIA NeMo Guardrails (see [Comparison](#comparison-with-nemo-guardrails)).

> **Status legend:** [x] implemented | [ ] TODO (planned, not implemented yet)

---

## Features

| Status | Feature | Description |
|---|---|---|
| [x] | **Prompt injection guard** | Blocks known jailbreak phrases such as *ignore previous instructions* or *reveal your system prompt* (9 case-insensitive English regex patterns). |
| [x] | **PII redactor** | Replaces emails, credit card numbers (Luhn checked), Hungarian TAJ numbers (checksum checked) and API keys (OpenAI, GitHub, Slack, Bearer) with `[REDACTED_*]` tokens. |
| [x] | **Threat intelligence: URLs** | Checks up to 3 URLs per prompt against the VirusTotal API (async). Runs on the already redacted text. |
| [x] | **Request authentication** | Optional shared secret (`GUARDRAIL_TOKEN`) sent in the `x-api-key` header. |
| [x] | **Safe logging** | The raw prompt is never logged or returned. Logs only contain the prompt length. |
| [x] | **Request size limit** | Bodies larger than 16 KB are rejected. |
| [ ] | **Threat intelligence: IP addresses** | Look up IPs found in prompts on VirusTotal (URLs only for now). |
| [ ] | **Text normalization** | Unicode NFKC and zero-width character removal before the injection check, to stop simple obfuscation. |
| [ ] | **Gemini API call** | Forward the sanitized prompt to the LLM and return its answer (the proxy currently only returns the sanitized prompt). |
| [ ] | **Output Canary Guard** | Put a unique canary token into the system context and block responses that leak it. |
| [ ] | **Incident audit log** | Append a structured JSON record (timestamp, guard, reason, prompt hash, never the raw prompt) for every blocked request. |
| [ ] | **Rate limiting** | Limit the number of requests per client. |
| [ ] | **Benchmark** | Measure detection rate, false positives and latency on a small attack / benign prompt set. |

---

## System Architecture

The diagram shows the target design. Steps marked `(TODO)` are not implemented yet.

```text
[ Client / User ]
        │
        ▼ (HTTP POST /v1/chat)
┌────────────────────────────────────────────────────────┐
│                RUST GUARDRAIL PROXY                    │
│                                                        │
│  0. Auth              ──► x-api-key check              │
│  1. Input Guard       ──► Prompt Injection Filter      │
│  2. PII Redactor      ──► Email, Card, TAJ, API keys   │
│  3. Threat Intel Tool ──► VirusTotal URL lookup        │
└───────────────────────────┬────────────────────────────┘
                            │ (Sanitized & Redacted Prompt)
                            ▼
┌────────────────────────────────────────────────────────┐
│        LLM PROVIDER (Gemini API)           (TODO)      │
└───────────────────────────┬────────────────────────────┘
                            │ (Raw Model Response)
                            ▼
┌────────────────────────────────────────────────────────┐
│  4. Output Guard      ──► Canary Token Filter  (TODO)  │
│  5. Audit Skill       ──► Incident Log         (TODO)  │
└───────────────────────────┬────────────────────────────┘
                            │ (Safe Response / Audit Log)
                            ▼
                 [ Client / User ]
```

Project layout:

```text
src/
  main.rs                   HTTP server, auth, request pipeline
  guards/
    prompt_injection.rs     injection regex guard
    pii_redactor.rs         PII and secret redaction (Luhn / TAJ checks)
  tools/
    threat_intel.rs         VirusTotal URL lookup (async)
```

---

## Quick Start

```powershell
git clone <repository-url>
cd Rust-guardrail
copy .env.example .env      # then fill in the values
cargo test                  # run the unit tests
cargo run                   # start the proxy on http://127.0.0.1:3000
```

### Configuration (`.env`)

| Variable | Required | Description |
|---|---|---|
| `GUARDRAIL_TOKEN` | recommended | Clients must send this value in the `x-api-key` header. If empty, authentication is disabled. |
| `VIRUSTOTAL_API_KEY` | optional | Enables URL checks. If empty, URL checks are skipped. |
| `PORT` | optional | Listening port (default `3000`). |
| `GEMINI_API_KEY` | not used yet | Reserved for the Gemini call (TODO). |

Never commit `.env`. It is already listed in `.gitignore`.

---

## Usage

```powershell
curl.exe -X POST http://127.0.0.1:3000/v1/chat `
  -H "Content-Type: application/json" `
  -H "x-api-key: <GUARDRAIL_TOKEN>" `
  -d '{"prompt":"Email test@example.com, card 4111 1111 1111 1111"}'
```

Response (200):

```json
{
  "sanitized_prompt": "Email [REDACTED_EMAIL], card [REDACTED_CARD]",
  "status": "PASSED_GUARDRAILS",
  "blocked": false
}
```

| HTTP code | `status` | Meaning |
|---|---|---|
| 200 | `PASSED_GUARDRAILS` | Prompt is clean or was redacted. |
| 401 | `UNAUTHORIZED` | Missing or wrong `x-api-key`. |
| 403 | `INJECTION_BLOCKED` | Prompt injection pattern detected. |
| 403 | `MALICIOUS_URL_BLOCKED` | VirusTotal flagged a URL in the prompt. |
| 413 | (empty) | Request body larger than 16 KB. |

---

## Security Design Decisions

* **No raw prompt in logs or responses:** prompts may contain PII and are attacker-controlled (log injection).
* **Redact before any external call:** the VirusTotal lookup only sees the redacted text.
* **Checksums reduce false positives:** a 16-digit order number is not redacted unless it passes the Luhn check; the same applies to TAJ numbers.
* **Constant-time token comparison** for `GUARDRAIL_TOKEN`.
* **Shared state built once:** regexes and the HTTP client are compiled at startup, not per request.

---

## Comparison with NeMo Guardrails

| Aspect | Rust Guardrail | NeMo Guardrails |
|---|---|---|
| Approach | Deterministic: regex, checksums, API lookup | Colang flows plus optional LLM-based checks |
| Extra LLM calls | None | Often one or more per check |
| Predictability | Same input gives the same result | Probabilistic when LLM-based |
| Paraphrased or semantic attacks | Weak (pattern based) | Better |
| Dialog and topic control | Not supported | Supported |
| Hungarian PII (TAJ) | Supported | Not built in |
| Maturity | Course prototype | Production framework |

The two approaches are complementary: a fast deterministic layer first, a semantic layer behind it. Measured numbers (detection rate, false positives, latency) will be added once the benchmark is done (TODO).

---

## Known Limitations

* The injection guard is a blacklist. Synonyms, other languages, encodings and look-alike Unicode characters can bypass it.
* Only English injection phrases are covered.
* Only the first 3 URLs of a prompt are checked. IP addresses are not checked.
* If VirusTotal cannot be reached, the URL is treated as safe (fail-open).
* PII coverage is limited to emails, cards, TAJ numbers and a few API key formats.
* No rate limiting, no TLS (run behind a reverse proxy) and the server listens on localhost only.

---

## Testing

```powershell
cargo test
```

The unit tests cover the injection patterns, every redaction type (including invalid card and TAJ numbers that must stay untouched) and URL extraction. Tests for the VirusTotal network call are TODO.

---

## TODO Summary

- [ ] IP address lookup
- [ ] Text normalization before the injection check
- [ ] Gemini API call
- [ ] Output Canary Guard
- [ ] Incident audit log
- [ ] Rate limiting
- [ ] Benchmark against a prompt set (and NeMo, if time allows)
