mod guards;
mod tools;

use axum::{routing::post, Json, Router};
use guards::pii_redactor::PiiRedactor;
use guards::prompt_injection::PromptInjectionGuard;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Deserialize)]
struct ChatRequest {
    prompt: String,
}

#[derive(Serialize)]
struct ChatResponse {
    original_prompt: String,
    sanitized_prompt: String,
    status: String,
    blocked: bool,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let app = Router::new().route("/v1/chat", post(handle_chat));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🛡️  Rust Guardrail Proxy running on: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_chat(Json(payload): Json<ChatRequest>) -> Json<ChatResponse> {
    let injection_guard = PromptInjectionGuard::new();
    let redactor = PiiRedactor::new();

    // 1. GUARD PHASE: Check for Prompt Injection
    if injection_guard.is_injection(&payload.prompt) {
        println!("\n🚨 [ALERT] Prompt Injection Attack Intercepted!");
        println!("  Blocked Prompt: {}\n", payload.prompt);

        return Json(ChatResponse {
            original_prompt: payload.prompt.clone(),
            sanitized_prompt: "[BLOCKED_BY_GUARDRAIL]".to_string(),
            status: "INJECTION_BLOCKED".to_string(),
            blocked: true,
        });
    }

    // 2. GUARD PHASE: Sanitize PII
    let sanitized = redactor.redact(&payload.prompt);

    println!("\n--------------------------------------------------");
    println!("📥 Incoming Prompt:  {}", payload.prompt);
    println!("🛡️  Sanitized Prompt: {}", sanitized);
    println!("--------------------------------------------------\n");

    Json(ChatResponse {
        original_prompt: payload.prompt,
        sanitized_prompt: sanitized,
        status: "PASSED_GUARDRAILS".to_string(),
        blocked: false,
    })
}