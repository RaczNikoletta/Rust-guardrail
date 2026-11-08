mod guards;

use axum::{routing::post, Json, Router};
use guards::pii_redactor::PiiRedactor;
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
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Define Axum application routes
    let app = Router::new().route("/v1/chat", post(handle_chat));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🛡️  Rust Guardrail Proxy running on: http://{}", addr);

    // Bind and start the HTTP server
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_chat(Json(payload): Json<ChatRequest>) -> Json<ChatResponse> {
    // Instantiate PII Redactor and sanitize incoming prompt
    let redactor = PiiRedactor::new();
    let sanitized = redactor.redact(&payload.prompt);

    Json(ChatResponse {
        original_prompt: payload.prompt,
        sanitized_prompt: sanitized,
        status: "PII_CHECK_PASSED".to_string(),
    })
}