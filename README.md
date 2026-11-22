# Rust Guardrail: AI Safety & Privacy Proxy

**Rust Guardrail** is a small proxy written in Rust (axum) that sits between a client application and a Large Language Model (LLM) API such as Google Gemini. It checks every prompt **before** it reaches the model.

It uses deterministic checks only (regex, checksums and an API lookup). This makes it cheap (no extra LLM calls for guarding), predictable and easy to unit test. It is a university project and a first line of defense, not a replacement for full frameworks such as NVIDIA NeMo Guardrails (see [Comparison](#comparison-with-nemo-guardrails)).

> **Status legend:** [x] implemented | [ ] TODO (planned, not implemented yet) | [~] optional extension / future work (not part of the core assignment, not implemented yet)

---

## Features

| Status | Feature | Description |
|---|---|---|
| [x] | **Prompt injection guard** | Blocks known jailbreak phrases such as *ignore previous instructions* or *reveal your system prompt* (9 case-insensitive English regex patterns). |
| [x] | **PII redactor** | Replaces emails, credit card numbers (Luhn checked), Hungarian TAJ numbers (checksum checked) and API keys (OpenAI, GitHub, Slack, Bearer) with `[REDACTED_*]` tokens. |
| [x] | **Threat intelligence: URLs** | Checks up to 3 URLs per prompt against the VirusTotal API (async). Runs on the already redacted text. |
| [x] | **Threat intelligence: IP addresses** | Checks up to 3 public IPv4 addresses per prompt against VirusTotal. Private, loopback and invalid addresses are skipped. |
| [x] | **Request authentication** | Optional shared secret (`GUARDRAIL_TOKEN`) sent in the `x-api-key` header. |
| [x] | **Safe logging** | The raw prompt is never logged or returned. Logs only contain the prompt length. |
| [x] | **Request size limit** | Bodies larger than 16 KB are rejected. |
| [x] | **Text normalization** | Unicode NFKC and removal of zero-width / control characters before every guard. Look-alike Cyrillic and Greek letters are folded to Latin for the injection check only. |
| [x] | **Gemini API call** | Sends the sanitized prompt (never the raw one) to Gemini and returns the answer in the `answer` field. Skipped if `GEMINI_API_KEY` is empty. |
| [x] | **Output Canary Guard** | A random canary token is hidden in the system instruction of every Gemini call. If it appears in the answer (even spaced out or with invisible characters), the answer is blocked. |
| [x] | **Incident audit log** | `src/tools/audit.rs` appends one JSON line (timestamp, guard, status, prompt length, SHA-256 of the prompt, never the raw prompt) to `audit.jsonl` for every blocked request. |
| [x] | **Incident report skill** | `audit/report.py` reads the log, computes statistics and asks Gemini to write a short incident report from the aggregated numbers (definition in `skills/incident-audit/SKILL.md`). |
| [x] | **Rate limiting** | `src/guards/rate_limit.rs` limits the requests per API key (fixed window, default 60 per minute, `RATE_LIMIT_PER_MINUTE`). Over the limit the proxy answers 429 before any guard, VirusTotal or Gemini work is done. |
| [x] | **Benchmark script** | `benchmark/run_benchmark.py` (Python, standard library only for the Rust proxy; the NeMo comparison is optional) sends 57 prompts to a running proxy and reports the detection rate per attack category, PII redaction, false positives and latency. The measured results are in [Benchmark Evaluation](#benchmark-evaluation). |
| [~] | **File upload guard** (optional extension) | Check uploaded text files (size, extension, file name, UTF-8) and run their content through the same guards as a prompt (normalization, injection, PII). Look up the SHA-256 hash on VirusTotal without uploading the file. See [Future Work](#future-work-not-part-of-the-core-assignment). |

---

## System Architecture

The diagram shows the design. Steps marked `(TODO)` are not implemented yet (currently none).

```text
[ Client / User ]
        │
        ▼ (HTTP POST /v1/chat)
┌────────────────────────────────────────────────────────┐
│                RUST GUARDRAIL PROXY                    │
│                                                        │
│  0. Auth + Rate limit ──► x-api-key, requests/minute   │
│  1. Normalizer        ──► NFKC, invisible chars removed│
│  2. Input Guard       ──► Prompt Injection Filter      │
│  3. PII Redactor      ──► Email, Card, TAJ, API keys   │
│  4. Threat Intel Tool ──► VirusTotal URL + IP lookup   │
└───────────────────────────┬────────────────────────────┘
                            │ (Sanitized & Redacted Prompt)
                            ▼
┌────────────────────────────────────────────────────────┐
│        LLM PROVIDER (Gemini API)                       │
└───────────────────────────┬────────────────────────────┘
                            │ (Raw Model Response)
                            ▼
┌────────────────────────────────────────────────────────┐
│  5. Output Guard      ──► Canary Token Filter          │
│  6. Audit Skill       ──► audit.jsonl + report         │
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
    normalize.rs            Unicode normalization and homoglyph folding
    prompt_injection.rs     injection regex guard
    pii_redactor.rs         PII and secret redaction (Luhn / TAJ checks)
    output_canary.rs        canary token check on the model's answer
    rate_limit.rs           fixed-window rate limiter per API key
  tools/
    threat_intel.rs         VirusTotal URL and IP lookup (async)
    gemini.rs               Gemini API client (async)
    audit.rs                incident audit log (JSON Lines, append only)
audit/
  report.py                 incident report skill (statistics + Gemini report)
skills/
  incident-audit/SKILL.md   skill definition
benchmark/
  run_benchmark.py          Python benchmark script (talks to the proxy over HTTP, optional NeMo comparison)
  nemo_config/              NeMo Guardrails config used by --target nemo
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
| `VIRUSTOTAL_API_KEY` | optional | Enables URL and IP checks. If empty, they are skipped. |
| `PORT` | optional | Listening port (default `3000`). |
| `GEMINI_API_KEY` | optional | Enables the Gemini call. If empty, prompts are only guarded and `answer` is `null`. |
| `GEMINI_MODEL` | optional | Gemini model name (default `gemini-2.5-flash`). |
| `AUDIT_LOG_PATH` | optional | Incident log file (default `audit.jsonl`). |
| `RATE_LIMIT_PER_MINUTE` | optional | Max requests per API key per minute (default `60`, `0` turns the limit off). |

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
  "blocked": false,
  "answer": "...the model's answer, or null if the LLM call is disabled..."
}
```

| HTTP code | `status` | Meaning |
|---|---|---|
| 200 | `PASSED_GUARDRAILS` | Prompt is clean or was redacted. |
| 401 | `UNAUTHORIZED` | Missing or wrong `x-api-key`. |
| 403 | `INJECTION_BLOCKED` | Prompt injection pattern detected. |
| 403 | `MALICIOUS_URL_BLOCKED` | VirusTotal flagged a URL in the prompt. |
| 403 | `MALICIOUS_IP_BLOCKED` | VirusTotal flagged an IP address in the prompt. |
| 403 | `OUTPUT_BLOCKED` | The model's answer contained the secret canary (instruction leak). |
| 413 | (empty) | Request body larger than 16 KB. |
| 429 | `RATE_LIMITED` | Too many requests for this API key in the current minute. |
| 502 | `LLM_ERROR` | The Gemini call failed (network error, timeout, API error or no answer). |

---

## Incident Audit Log and Report Skill

Every request blocked by a guard (injection, malicious URL, malicious IP, canary leak) is appended as one line to `audit.jsonl`:

```json
{"ts_unix":1700000000,"guard":"injection","status":"INJECTION_BLOCKED","http":403,"prompt_len":30,"prompt_sha256":"ca97...","detail":"pattern match"}
```

| Field | Meaning |
|---|---|
| `ts_unix` | Time in seconds since 1970-01-01 UTC. |
| `guard` | Which guard fired (`injection`, `malicious_url`, `malicious_ip`, `output_canary`). |
| `status` | The status string the client received. |
| `http` | HTTP status code. |
| `prompt_len` | Length of the normalized prompt in bytes. |
| `prompt_sha256` | SHA-256 fingerprint of the normalized prompt. The same attack sent twice gives the same hash. |
| `detail` | Short reason written by the code (counts or lengths), never user text. |

The raw prompt and the model's answer are never stored. A failed log write only prints a warning; it never stops the proxy.

The report skill reads the log and writes a summary:

```powershell
python benchmark/run_benchmark.py        # create some incidents
python audit/report.py                   # statistics + Gemini report (needs GEMINI_API_KEY)
python audit/report.py --no-llm          # statistics only
```

The script skips malformed lines and sends only aggregated numbers to Gemini, never single records.

Example (`--no-llm`) after repeated benchmark runs:

```text
=== Incident statistics ===
Total incidents : 191
Skipped lines   : 0
Period          : 2026-11-20 12:00 UTC  ->  2026-11-22 09:00 UTC
By guard:
  injection       189
  output_canary   2
By status:
  INJECTION_BLOCKED       189
  OUTPUT_BLOCKED          2
Busiest hour    : 2026-11-22 09:00 UTC (58 incidents)
Repeated prompts (same SHA-256):
  32126a0c69d7...  x30  injection
  b70607ca30f3...  x10  injection
  ...
Prompt length   : min 25, avg 47.7, max 94 bytes
```

The data comes from benchmark runs, not from real traffic: the repeated hashes (`x10`) show that the prompts were sent about ten times, and the busiest hour is the latest benchmark run. The 189 `injection` incidents include the one known false positive.

The 2 `output_canary` incidents are cases where a prompt passed all input guards, but Gemini's answer contained the secret canary. The proxy printed `[ALERT] Canary found in the model's answer, answer blocked` and returned `OUTPUT_BLOCKED` instead of the answer. This is the second layer working: the blacklist did not catch the prompt, the output guard did. The canary check only runs when Gemini is enabled, so the benchmark runs with an empty `GEMINI_API_KEY` measure the input guards only.

---

## Security Design Decisions

* **Normalize first:** all guards see the same canonical text, so zero-width characters, full-width letters or look-alike letters cannot hide an attack from one guard but not another.
* **No raw prompt in logs or responses:** prompts may contain PII and are attacker-controlled (log injection).
* **Redact before any external call:** the VirusTotal lookup only sees the redacted text.
* **Checksums reduce false positives:** a 16-digit order number is not redacted unless it passes the Luhn check; the same applies to TAJ numbers.
* **Constant-time token comparison** for `GUARDRAIL_TOKEN`.
* **Shared state built once:** regexes and the HTTP client are compiled at startup, not per request.

---

## Why Rust?

The proxy parses attacker-controlled text and sits on the critical path of every request, so the choice of language matters.

* **Memory safety without a garbage collector.** Buffer overflows and use-after-free (a common vulnerability class in C/C++) are ruled out at compile time. The project contains no `unsafe` code.
* **Data-race freedom.** State shared between concurrent requests (`Arc<AppState>`) must be thread-safe, otherwise the code does not compile.
* **Errors are part of the type system.** `Option` and `Result` force the code to handle missing fields (for example a blocked Gemini answer) and failed network calls. There are no null pointers.
* **ReDoS-resistant regex.** The `regex` crate matches in linear time, so a crafted prompt cannot freeze the guards. Trade-off: no lookaround and no backreferences.
* **Low, predictable overhead.** No GC pauses and a single static binary (no runtime to install). Measured guard time: median 17.5 ms per request, p95 27.9 ms (see Benchmark Evaluation).

| | Rust | C++ | Go | Python | Java / C# |
|---|---|---|---|---|---|
| Memory safety | compile time | no | yes (GC) | yes (GC) | yes (GC) |
| Data races | rejected by the compiler | possible | runtime race detector | logic errors possible | runtime |
| Missing value / errors | `Option` / `Result`, enforced | `nullptr`, exceptions | `nil`, `error` convention | `None`, exceptions | `null`, exceptions |
| Regex engine | linear time (crate) | library dependent | linear time | backtracking (ReDoS risk) | backtracking by default |
| GC pauses | none | none | yes | yes | yes |
| Runtime needed | no | no | small (built in) | yes | yes |
| AI / NLP ecosystem | weak | weak | weak | **excellent** | medium |
| Learning curve | **steep** | steep | gentle | gentle | medium |

**Trade-offs.** Rust has a steeper learning curve and slower prototyping than Python, and a much weaker AI/NLP ecosystem. This is why semantic detection is out of scope and a hybrid design with a Python layer is suggested (see the comparison below). Rust does not fix logic flaws: the blacklist-based injection guard is as bypassable in Rust as in any other language, and security details such as the constant-time token comparison still have to be written by hand. Go would also have been a reasonable choice (memory safe, simple, good HTTP support); Rust was preferred for its type system and the absence of a GC.

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

The two approaches are complementary: a fast deterministic layer first, a semantic layer behind it. The measured numbers are in [Benchmark Evaluation](#benchmark-evaluation).

---

## Known Limitations

* The injection guard is a blacklist. Synonyms, other languages and encodings (e.g. Base64) can bypass it.
* Homoglyph folding covers only common Cyrillic and Greek look-alikes, not the full Unicode confusables table.
* The text that is forwarded is the normalized prompt, so the original bytes (zero-width joiners in emoji, decomposed accents) are not preserved.
* Only English injection phrases are covered.
* Only the first 3 URLs and the first 3 public IPv4 addresses of a prompt are checked. IPv6 is not checked.
* Version numbers such as `1.2.3.4` look like IP addresses and are looked up too (harmless, but they use VirusTotal quota).
* If VirusTotal cannot be reached, the URL or IP is treated as safe (fail-open).
* The model's answer is checked only for the canary. Other harmful content in the answer is not detected, and an answer that encodes the canary (e.g. Base64) or only repeats a part of the instructions passes.
* Every request is a single turn: there is no conversation history. If the Gemini call fails, the request is not retried.
* PII coverage is limited to emails, cards, TAJ numbers and a few API key formats.
* No TLS (run behind a reverse proxy) and the server listens on localhost only.
* Rate limiting is per API key. With one `GUARDRAIL_TOKEN` all clients share one counter, so it is effectively a global limit. If authentication is disabled, all requests share one counter. Fixed windows allow a short burst of up to twice the limit at a window boundary. The counters are in memory and reset on restart. The 429 response has no `Retry-After` header yet.
* Only the chat prompt is checked. Uploaded files are not supported yet (see Future Work).
* The audit log has no tamper protection (no hash chain or signature). It is one local file with a 5 MB limit and no rotation; when it is full, new incidents are not written.
* The prompt hash is a plain SHA-256, so a short or guessable prompt could be recovered by brute force. Treat the log as sensitive.
* Failed logins (401) and rate-limited requests (429) are not logged on purpose, so callers cannot fill the disk.

---

## Future Work (not part of the core assignment)

Nothing in this section is implemented. It is marked `[~]` and is meant as an optional extension or as a direction for continuing the project.

**File upload guard.** Uploaded documents are a main route of *indirect prompt injection*: the attack is hidden in the file, not typed into the chat. The model reads the file content as part of the prompt, so the existing guards are useful here too.

| Check | What it catches | Effort |
|---|---|---|
| Size limit | huge files, memory use | easy |
| Extension allowlist (`.txt`, `.md`, `.csv`) | dangerous types (`.exe`, `.js`) | easy |
| File name cleaning (`../`, `\`, double extensions such as `image.jpg.exe`) | path traversal | easy |
| UTF-8 check for text files | binary garbage, encoding tricks | easy |
| Content through the existing guards (normalize, injection, PII) | hidden instructions, personal data inside the document | easy, if the guard steps are moved into one shared function |
| Magic bytes vs. extension | a renamed file (an `.exe` pretending to be `.txt`) | medium |
| SHA-256 hash lookup on VirusTotal (`GET /files/{hash}`) | known malicious files. Only the hash leaves the proxy, not the file | medium |
| PDF / Office text extraction, macro detection (`vbaProject.bin`), zip-bomb limits, hidden text, OCR | complex attacks | hard |

Suggested scope:

* **Optional extension:** text files only (`.txt`, `.md`, `.csv`), with the checks marked easy plus the hash lookup. This needs the axum `multipart` feature, a SHA-256 crate, a new `POST /v1/upload` endpoint and a shared `run_guards()` function used by both endpoints.
* **Continuing the project:** everything else in the table (PDF / Office, archives, OCR).

---

## Testing

```powershell
cargo test
```
<img width="1479" height="586" alt="image" src="https://github.com/user-attachments/assets/26478e1f-2208-46d8-ba2a-57b778e6b8ce" />




The unit tests cover normalization (zero-width, full-width and look-alike characters), the injection patterns, every redaction type (including invalid card and TAJ numbers that must stay untouched) URL and IP extraction, the Gemini request and response handling, the canary guard, the rate limiter (limit, window expiry, separate keys) and the audit log (hashing, one-line JSON records, appending and the size limit).

---

## Benchmark

The benchmark is a separate Python script. It talks to the proxy over HTTP, so the Rust code is not touched, and the Rust mode needs no `pip install`. Only the optional NeMo comparison needs extra packages.

```powershell
cargo run                                # terminal 1: start the proxy
python benchmark/run_benchmark.py        # terminal 2: run the benchmark
```

Options: `--target` (`rust`, `nemo` or `both`, default `rust`), `--url` (default `http://127.0.0.1:3000/v1/chat`), `--token` (default: `GUARDRAIL_TOKEN` from the environment or `.env`), `--nemo-config`, `--delay` (seconds between requests, useful against Gemini rate limits), `--timeout`.

For guard-only latency, leave `GEMINI_API_KEY` empty in `.env` while benchmarking. Otherwise every prompt that passes the guards also waits for the Gemini answer. Set `RATE_LIMIT_PER_MINUTE=0` while benchmarking: the script sends 57 prompts quickly and a second run within a minute would hit the default limit (the script retries a 429 twice, then counts the prompt as an error). The prompts contain no URLs or IP addresses, so VirusTotal quota is not used.

| Group | Prompts | Counted as correct when |
|---|---|---|
| Attacks: `direct` | 10, one per injection pattern | the request is blocked |
| Attacks: `obfuscated` | 8, the same attacks hidden with upper case, extra whitespace, zero-width or soft-hyphen characters, full-width letters, Cyrillic look-alikes | the request is blocked |
| Attacks: `paraphrase` | 9, other words, Hungarian and French, Base64, leetspeak, a punctuated phrase, role play | the request is blocked. **Most are expected to be missed**: the guard is a blacklist, and the benchmark shows this on purpose. |
| PII | 10: email, card, TAJ, three key formats, full-width digits, a hidden zero-width space, a mixed prompt | not blocked, and the secret is gone from `sanitized_prompt` |
| Benign: `normal` | 12, English and Hungarian | not blocked and returned unchanged |
| Benign: `tricky` | 8, close to the attack patterns or looking like PII (git blame, order numbers, dates, version numbers) | not blocked and returned unchanged. One prompt that quotes an attack phrase is a known false positive. |

The script prints one line per prompt, then the rates per group, the false positives, the prompts that were altered by mistake, and the latency (median, p95, max; blocked requests alone give the pure guard time because they never reach Gemini or VirusTotal). The full results are saved to `benchmark/results.json` (one entry per target).

### Comparison with NeMo Guardrails

`--target both` runs the same prompts through the Rust proxy and through NeMo Guardrails and prints the results side by side.

```powershell
pip install nemoguardrails
$env:OPENAI_API_KEY = "<same value as GEMINI_API_KEY>"   # NeMo reaches Gemini through its OpenAI-compatible endpoint
python benchmark/run_benchmark.py --target both --delay 1.5
```

NeMo is configured in `benchmark/nemo_config/` with one input rail (`self check input`, an LLM call per prompt) and runs in-process. Only the input rail runs, so the main model never answers; the measured latency is the guard check including its one LLM call (model `gemini-3.5-flash-lite`). Differences to keep in mind:

* The NeMo configuration has no PII rail: `self check input` only decides (block or pass) and returns no redacted prompt, so there is nothing to check, and the 10 PII cases are run for the Rust proxy only. NeMo has a built-in Presidio-based sensitive data rail that was not enabled here, and Hungarian TAJ numbers would need a custom recognizer. For the benign prompts, NeMo is only checked for not blocking.
* The self-check is an LLM, so its result can change between runs. The first NeMo call (warm-up) is not measured.
* NeMo's engine name and rail API depend on the installed version; check `benchmark/nemo_config/config.yml` if the model fails to load.

<img width="712" height="40" alt="image" src="https://github.com/user-attachments/assets/634fa880-b947-413d-8551-2ee4be31b152" />

<img width="1551" height="593" alt="image" src="https://github.com/user-attachments/assets/567edde2-4a89-4c9d-961f-33db24fd27e8" />

### Benchmark Evaluation

The guardrail caught **100% (18/18)** of direct and obfuscated prompt injection attempts, redacted **100% (10/10)** of PII test cases, and passed **12/12** normal benign prompts with **0/20** accidental redactions. Overall attack detection is **66.7% (18/27)** because `paraphrase` attacks (`0/9`) remain a known limitation. There was **1/20** false positive on a benign security-course prompt quoting `"ignore previous instructions"`.

Latency (Rust proxy with `GEMINI_API_KEY` empty, so only the guards run, including the local HTTP round trip): median **17.5 ms**, p95 **27.9 ms** over all 57 prompts.

Rust vs. NeMo `self check input` (the 10 PII cases are Rust only; NeMo makes one Gemini call per prompt):

| | Rust Guardrail | NeMo |
|---|---|---|
| Direct + obfuscated attacks | 18/18 | 18/18 |
| Paraphrase attacks | 0/9 | 9/9 |
| All attacks | 18/27 | 27/27 |
| False positives (benign) | 1/20 | 0/20 |
| LLM calls per prompt | 0 | 1 |
| Median latency (blocked prompts) | 17.3 ms | 1106 ms |
| p95 latency (blocked prompts) | 30.0 ms | 6444 ms |

NeMo detects more, mainly the paraphrased attacks. The Rust guard is about 60 times faster, needs no LLM call, gives the same result every run, and redacts PII before anything leaves the proxy. NeMo's latency is mostly the Gemini call and varies with the API load.

**How it was measured.** One run of `python benchmark/run_benchmark.py --target both --delay 1.5`: 57 prompts through the Rust proxy (`GEMINI_API_KEY` empty, so only the guards ran) and 47 through NeMo (no PII cases). NeMo's `self check input` called `gemini-3.5-flash-lite`. This is a small sample, and NeMo's result comes from an LLM and can change between runs, so the numbers are good for comparing orders of magnitude, not for exact percentages. The Rust numbers measure the input guards only: the output canary guard needs a Gemini answer, so it did not run with an empty `GEMINI_API_KEY`.

**Limits of the test set.** The test prompts were written together with the guard. The `direct` and `obfuscated` prompts follow the guard's own patterns, so 18/18 shows that the guard recognises its own patterns and is not a general detection rate. The `paraphrase` group is the independent part of the test, and there the Rust guard catches none.

---

## AI Assistance

| Tool | Used for |
|---|---|
| Claude | most of the code development (guards, proxy, benchmark) and the documentation |
| ChatGPT | planning and design |
| Gemini | the initial code architecture and debugging runtime errors |

The behaviour of the code is checked by the unit tests and the benchmark.



---

## TODO Summary

- [~] File upload guard (optional extension, see Future Work)
