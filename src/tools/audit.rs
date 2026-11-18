use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

/// Used when `AUDIT_LOG_PATH` is not set. The file is created next to where the proxy is started.
const DEFAULT_LOG_PATH: &str = "audit.jsonl";

/// Once the file is this big, new incidents are no longer written (see `append`).
/// Without a limit, an attacker who keeps triggering a guard could fill the disk.
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// One incident = one line in the log file (JSON Lines format).
///
/// It holds metadata only. The prompt itself is NEVER stored: it may contain PII and it is
/// attacker-controlled. Only its length and a SHA-256 fingerprint are kept, so the same
/// attack sent twice can be recognised without keeping its text.
#[derive(Serialize)]
struct AuditRecord {
    /// Seconds since 1970-01-01 UTC (a plain number needs no extra date library).
    ts_unix: u64,
    /// Which guard fired, e.g. "injection".
    guard: &'static str,
    /// The same status string the client receives, e.g. "INJECTION_BLOCKED".
    status: &'static str,
    http: u16,
    /// Length of the (normalized) prompt in bytes.
    prompt_len: usize,
    prompt_sha256: String,
    /// A short reason written by our own code (counts, lengths), never user text.
    detail: String,
}

pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    /// Only one request writes at a time, so two lines can never be mixed together.
    write_lock: Mutex<()>,
}

impl AuditLog {
    /// Reads `AUDIT_LOG_PATH` (default `audit.jsonl`). The path comes from the operator's own
    /// environment, not from a request.
    pub fn new() -> Self {
        let path = env::var("AUDIT_LOG_PATH")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| DEFAULT_LOG_PATH.to_string());

        println!("[INFO] Incident audit log: {}", path);
        Self::with_path(PathBuf::from(path), MAX_LOG_BYTES)
    }

    pub fn with_path(path: PathBuf, max_bytes: u64) -> Self {
        Self { path, max_bytes, write_lock: Mutex::new(()) }
    }

    /// Writes one incident. It never returns an error: if the log cannot be written, a warning
    /// is printed and the request carries on. A broken log must not take the proxy down.
    pub async fn record(
        &self,
        guard: &'static str,
        status: &'static str,
        http: u16,
        prompt: &str,
        detail: String,
    ) {
        let record = build_record(unix_now(), guard, status, http, prompt, detail);
        let line = to_line(&record);
        if line.is_empty() {
            return;
        }

        let _lock = self.write_lock.lock().await;
        if let Err(e) = self.append(&line).await {
            println!("[WARN] Could not write the audit log: {}", e);
        }
    }

    /// Appends one line, unless the file has reached its size limit.
    async fn append(&self, line: &str) -> Result<(), String> {
        let size = tokio::fs::metadata(&self.path)
            .await
            .map(|m| m.len())
            .unwrap_or(0); // no file yet = size 0
        if size >= self.max_bytes {
            return Err(format!("the log is full ({} bytes), incident not written", size));
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| e.to_string())?;

        file.write_all(format!("{}\n", line).as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        file.flush().await.map_err(|e| e.to_string())
    }
}

/// Seconds since the Unix epoch. Falls back to 0 if the clock is before 1970.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// SHA-256 of the text as 64 lowercase hex characters.
fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

/// Puts the pieces together. The prompt is only used to compute its length and its hash.
fn build_record(
    ts_unix: u64,
    guard: &'static str,
    status: &'static str,
    http: u16,
    prompt: &str,
    detail: String,
) -> AuditRecord {
    AuditRecord {
        ts_unix,
        guard,
        status,
        http,
        prompt_len: prompt.len(),
        prompt_sha256: sha256_hex(prompt),
        detail,
    }
}

/// The record as ONE line of JSON. `serde_json` escapes quotes and newlines, so text cannot
/// break out of its field and forge a second log line.
/// A struct of plain values always serializes; the empty fallback is never expected.
fn to_line(record: &AuditRecord) -> String {
    serde_json::to_string(record).unwrap_or_default()
}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("guardrail_{}_{}_{}.jsonl", name, std::process::id(), nanos))
    }

    #[test]
    fn test_sha256_known_value() {
        // Standard test vector for SHA-256("abc")
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_same_prompt_same_hash_different_prompt_different_hash() {
        assert_eq!(sha256_hex("attack"), sha256_hex("attack"));
        assert_ne!(sha256_hex("attack"), sha256_hex("attack!"));
    }

    #[test]
    fn test_record_is_one_line_and_never_contains_the_prompt() {
        let prompt = "line one\nline two \"quoted\" SECRET_MARKER_123";
        let record = build_record(1_700_000_000, "injection", "INJECTION_BLOCKED", 403, prompt, "pattern match".to_string());
        let line = to_line(&record);

        assert!(!line.contains('\n'));
        assert!(!line.contains("SECRET_MARKER_123"));

        // The line is valid JSON with the expected fields.
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["ts_unix"], 1_700_000_000u64);
        assert_eq!(parsed["guard"], "injection");
        assert_eq!(parsed["status"], "INJECTION_BLOCKED");
        assert_eq!(parsed["http"], 403);
        assert_eq!(parsed["prompt_len"], prompt.len());
        assert_eq!(parsed["prompt_sha256"], sha256_hex(prompt).as_str());
    }

    #[test]
    fn test_text_in_detail_cannot_forge_a_second_line() {
        let evil = "x\"}\n{\"guard\":\"fake\"".to_string();
        let record = build_record(1, "injection", "INJECTION_BLOCKED", 403, "p", evil);
        let line = to_line(&record);

        assert!(!line.contains('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["guard"], "injection");
    }

    #[tokio::test]
    async fn test_records_are_appended_one_per_line() {
        let path = temp_log_path("append");
        let log = AuditLog::with_path(path.clone(), MAX_LOG_BYTES);

        log.record("injection", "INJECTION_BLOCKED", 403, "first", "pattern match".to_string()).await;
        log.record("output_canary", "OUTPUT_BLOCKED", 403, "second", "answer_len=5".to_string()).await;

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["guard"], "injection");
        assert_eq!(second["guard"], "output_canary");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_full_log_stops_growing() {
        let path = temp_log_path("full");
        let log = AuditLog::with_path(path.clone(), 10); // tiny limit: one line already exceeds it

        log.record("injection", "INJECTION_BLOCKED", 403, "first", "pattern match".to_string()).await;
        log.record("injection", "INJECTION_BLOCKED", 403, "second", "pattern match".to_string()).await;

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);

        let _ = std::fs::remove_file(&path);
    }
}
