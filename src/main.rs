mod guards;
mod tools;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use guards::normalize::{fold_homoglyphs, normalize};
use guards::pii_redactor::PiiRedactor;
use guards::prompt_injection::PromptInjectionGuard;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, sync::Arc};
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
}

/// Everything is built once at startup and shared between requests.
struct AppState {
    injection_guard: PromptInjectionGuard,
    redactor: PiiRedactor,
    threat_intel: ThreatIntel,
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
        }),
    )
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
        threat_intel: ThreatIntel::new(),
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
    // 0. AUTH: only clients that know the token may use the proxy
    if let Some(expected) = &state.auth_token {
        let authorized = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map_or(false, |given| tokens_match(given, expected));
        if !authorized {
            return reply(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "[UNAUTHORIZED]", true);
        }
    }

    // 1. NORMALIZE: one canonical form (NFKC, no invisible characters) before any guard runs.
    // Every later step works on this text, so obfuscation cannot hide anything from them.
    let normalized = normalize(&payload.prompt);

    // 2. GUARD PHASE: Check for Prompt Injection
    // Look-alike letters are folded only for this check; the text that is forwarded keeps them.
    // Never log the prompt itself: it is attacker-controlled (log injection) and may hold PII.
    if state.injection_guard.is_injection(&fold_homoglyphs(&normalized)) {
        println!("[ALERT] Prompt injection blocked (prompt length: {} bytes)", payload.prompt.len());
        return reply(StatusCode::FORBIDDEN, "INJECTION_BLOCKED", "[BLOCKED_BY_GUARDRAIL]", true);
    }

    // 3. GUARD PHASE: Sanitize PII (full-width digits are plain digits by now, so they are caught)
    let sanitized = state.redactor.redact(&normalized);

    // 4. GUARD PHASE: Check URLs and IP addresses with VirusTotal.
    // This runs on the REDACTED text, so PII never leaves the proxy.
    let malicious_urls = state.threat_intel.find_malicious_urls(&sanitized).await;
    if !malicious_urls.is_empty() {
        println!("[ALERT] Malicious URL blocked ({} found)", malicious_urls.len());
        return reply(StatusCode::FORBIDDEN, "MALICIOUS_URL_BLOCKED", "[BLOCKED_BY_GUARDRAIL]", true);
    }

    let malicious_ips = state.threat_intel.find_malicious_ips(&sanitized).await;
    if !malicious_ips.is_empty() {
        println!("[ALERT] Malicious IP blocked ({} found)", malicious_ips.len());
        return reply(StatusCode::FORBIDDEN, "MALICIOUS_IP_BLOCKED", "[BLOCKED_BY_GUARDRAIL]", true);
    }

    println!("[INFO] Prompt passed the guardrails (length: {} bytes)", payload.prompt.len());
    reply(StatusCode::OK, "PASSED_GUARDRAILS", &sanitized, false)
}
