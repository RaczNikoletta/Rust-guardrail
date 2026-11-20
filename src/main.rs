mod guards;
mod tools;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use guards::normalize::{fold_homoglyphs, normalize};
use guards::output_canary::OutputCanaryGuard;
use guards::pii_redactor::PiiRedactor;
use guards::prompt_injection::PromptInjectionGuard;
use guards::rate_limit::RateLimiter;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, sync::Arc};
use tools::audit::AuditLog;
use tools::gemini::GeminiClient;
use tools::threat_intel::ThreatIntel;

/// Requests larger than this are rejected before they are parsed (HTTP 413).
const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
struct ChatRequest {
    prompt: String,
}

// The raw prompt is deliberately NOT part of the response: it may contain PII.
#[derive(Serialize)]
struct ChatResponse {
    sanitized_prompt: String,
    status: String,
    blocked: bool,
    /// The LLM's answer. `null` if the prompt was blocked or the LLM call is disabled.
    answer: Option<String>,
}

/// Everything is built once at startup and shared between requests.
struct AppState {
    injection_guard: PromptInjectionGuard,
    redactor: PiiRedactor,
    canary_guard: OutputCanaryGuard,
    threat_intel: ThreatIntel,
    gemini: GeminiClient,
    audit: AuditLog,
    rate_limiter: RateLimiter,
    /// If set, clients must send it in the `x-api-key` header.
    auth_token: Option<String>,
}

/// Compares two tokens without stopping at the first different byte (avoids timing leaks).
fn tokens_match(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn reply(code: StatusCode, status: &str, sanitized: &str, blocked: bool) -> (StatusCode, Json<ChatResponse>) {
    (
        code,
        Json(ChatResponse {
            sanitized_prompt: sanitized.to_string(),
            status: status.to_string(),
            blocked,
            answer: None,
        }),
    )
}

/// Every guard block goes through here: write the audit record, then answer 403.
/// `prompt` is the normalized prompt; the audit log keeps only its length and hash.
async fn block(
    state: &AppState,
    prompt: &str,
    guard: &'static str,
    status: &'static str,
    detail: String,
) -> (StatusCode, Json<ChatResponse>) {
    state.audit.record(guard, status, 403, prompt, detail).await;
    reply(StatusCode::FORBIDDEN, status, "[BLOCKED_BY_GUARDRAIL]", true)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let auth_token = env::var("GUARDRAIL_TOKEN").ok().filter(|t| !t.is_empty());
    if auth_token.is_none() {
        println!("[WARN] GUARDRAIL_TOKEN is not set. Authentication is disabled.");
    }

    let state = Arc::new(AppState {
        injection_guard: PromptInjectionGuard::new(),
        redactor: PiiRedactor::new(),
        canary_guard: OutputCanaryGuard::new(),
        threat_intel: ThreatIntel::new(),
        gemini: GeminiClient::new(),
        audit: AuditLog::new(),
        rate_limiter: RateLimiter::new(),
        auth_token,
    });

    let app = Router::new()
        .route("/v1/chat", post(handle_chat))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let port: u16 = env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("🛡️  Rust Guardrail Proxy running on: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_chat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChatRequest>,
) -> (StatusCode, Json<ChatResponse>) {
    // 0. AUTH: only clients that know the token may use the proxy.
    // Failed logins are deliberately NOT written to the audit log: anyone without the token
    // could otherwise fill the disk with junk requests.
    // `client_key` is only ever a key that passed the check (or a fixed name when auth is off),
    // so a caller cannot create new rate limit counters by inventing keys.
    let client_key: &str = match &state.auth_token {
        Some(expected) => {
            let authorized = headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map_or(false, |given| tokens_match(given, expected));
            if !authorized {
                return reply(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "[UNAUTHORIZED]", true);
            }
            expected.as_str()
        }
        None => "anonymous",
    };

    // 0b. RATE LIMIT: per API key. It runs before the expensive steps (guards, VirusTotal, Gemini).
    // Also not written to the audit log, so a flood cannot push real incidents out of the file.
    if let Err(wait) = state.rate_limiter.check(client_key) {
        println!("[WARN] Rate limit exceeded, retry in {} s", wait);
        return reply(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", "[RATE_LIMITED]", true);
    }

    // 1. NORMALIZE: one canonical form (NFKC, no invisible characters) before any guard runs.
    // Every later step works on this text, so obfuscation cannot hide anything from them.
    let normalized = normalize(&payload.prompt);

    // 2. GUARD PHASE: Check for Prompt Injection
    // Look-alike letters are folded only for this check; the text that is forwarded keeps them.
    // Never log the prompt itself: it is attacker-controlled (log injection) and may hold PII.
    if state.injection_guard.is_injection(&fold_homoglyphs(&normalized)) {
        println!("[ALERT] Prompt injection blocked (prompt length: {} bytes)", payload.prompt.len());
        return block(&state, &normalized, "injection", "INJECTION_BLOCKED", "pattern match".to_string()).await;
    }

    // 3. GUARD PHASE: Sanitize PII (full-width digits are plain digits by now, so they are caught)
    let sanitized = state.redactor.redact(&normalized);

    // 4. GUARD PHASE: Check URLs and IP addresses with VirusTotal.
    // This runs on the REDACTED text, so PII never leaves the proxy.
    let malicious_urls = state.threat_intel.find_malicious_urls(&sanitized).await;
    if !malicious_urls.is_empty() {
        println!("[ALERT] Malicious URL blocked ({} found)", malicious_urls.len());
        let detail = format!("urls={}", malicious_urls.len());
        return block(&state, &normalized, "malicious_url", "MALICIOUS_URL_BLOCKED", detail).await;
    }

    let malicious_ips = state.threat_intel.find_malicious_ips(&sanitized).await;
    if !malicious_ips.is_empty() {
        println!("[ALERT] Malicious IP blocked ({} found)", malicious_ips.len());
        let detail = format!("ips={}", malicious_ips.len());
        return block(&state, &normalized, "malicious_ip", "MALICIOUS_IP_BLOCKED", detail).await;
    }

    println!("[INFO] Prompt passed the guardrails (length: {} bytes)", payload.prompt.len());

    // 5. LLM CALL: only the sanitized text is ever sent to Gemini.
    // The canary is hidden in the system instruction of this call.
    let answer = if state.gemini.is_enabled() {
        match state.gemini.generate(&sanitized, state.canary_guard.canary()).await {
            Ok(text) => Some(text),
            Err(e) => {
                println!("[ERROR] Gemini call failed: {}", e);
                // 502: the proxy worked, but the service behind it did not
                return reply(StatusCode::BAD_GATEWAY, "LLM_ERROR", &sanitized, false);
            }
        }
    } else {
        None
    };

    // 6. OUTPUT GUARD: if the answer contains the canary, the model leaked its instructions.
    // The answer is dropped; it is not logged either.
    if let Some(text) = &answer {
        if state.canary_guard.leaks(text) {
            println!("[ALERT] Canary found in the model's answer, answer blocked");
            let detail = format!("answer_len={}", text.len());
            return block(&state, &normalized, "output_canary", "OUTPUT_BLOCKED", detail).await;
        }
    }

    (
        StatusCode::OK,
        Json(ChatResponse {
            sanitized_prompt: sanitized,
            status: "PASSED_GUARDRAILS".to_string(),
            blocked: false,
            answer,
        }),
    )
}
