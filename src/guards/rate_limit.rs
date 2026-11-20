use std::{
    collections::HashMap,
    env,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Requests per key per window, used when `RATE_LIMIT_PER_MINUTE` is not set.
const DEFAULT_LIMIT: u32 = 60;

/// Length of one counting window.
const WINDOW: Duration = Duration::from_secs(60);

/// Safety net: if the map ever grows beyond this, expired entries are removed.
const MAX_KEYS: usize = 1000;

/// The counter of one API key: when its window started and how many requests it has made since.
struct Window {
    started: Instant,
    count: u32,
}

/// Fixed-window rate limiter: every API key may make `limit` requests per window.
pub struct RateLimiter {
    /// 0 means "rate limiting is off".
    limit: u32,
    window: Duration,
    clients: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    /// Reads `RATE_LIMIT_PER_MINUTE` (default 60, `0` turns the limit off).
    pub fn new() -> Self {
        let limit = env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_LIMIT);

        if limit == 0 {
            println!("[WARN] Rate limiting is disabled (RATE_LIMIT_PER_MINUTE=0).");
        } else {
            println!("[INFO] Rate limit: {} requests per minute per API key", limit);
        }
        Self::with_limit(limit, WINDOW)
    }

    pub fn with_limit(limit: u32, window: Duration) -> Self {
        Self { limit, window, clients: Mutex::new(HashMap::new()) }
    }

    /// Counts one request of `key`. `Ok(())` = allowed; `Err(seconds)` = too many requests,
    /// try again after that many seconds.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    /// Same as `check`, but the current time is passed in, so tests do not have to sleep.
    fn check_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        if self.limit == 0 {
            return Ok(());
        }

        // The lock is held only for this short, non-async block. If another thread panicked
        // while holding it, the counters are still usable, so the poison flag is ignored.
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if clients.len() >= MAX_KEYS {
            let window = self.window;
            clients.retain(|_, w| now.saturating_duration_since(w.started) < window);
        }

        let w = clients
            .entry(key.to_string())
            .or_insert(Window { started: now, count: 0 });

        // The window is over: start a new one.
        if now.saturating_duration_since(w.started) >= self.window {
            w.started = now;
            w.count = 0;
        }

        if w.count >= self.limit {
            let left = self.window.saturating_sub(now.saturating_duration_since(w.started));
            return Err(left.as_secs().max(1));
        }

        w.count += 1;
        Ok(())
    }
}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_up_to_the_limit_then_blocks() {
        let limiter = RateLimiter::with_limit(3, Duration::from_secs(60));
        let t = Instant::now();

        assert!(limiter.check_at("key-a", t).is_ok());
        assert!(limiter.check_at("key-a", t).is_ok());
        assert!(limiter.check_at("key-a", t).is_ok());
        assert!(limiter.check_at("key-a", t).is_err());
    }

    #[test]
    fn test_window_expiry_allows_requests_again() {
        let limiter = RateLimiter::with_limit(1, Duration::from_secs(60));
        let t = Instant::now();

        assert!(limiter.check_at("key-a", t).is_ok());
        assert!(limiter.check_at("key-a", t + Duration::from_secs(30)).is_err());
        assert!(limiter.check_at("key-a", t + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn test_keys_are_counted_separately() {
        let limiter = RateLimiter::with_limit(1, Duration::from_secs(60));
        let t = Instant::now();

        assert!(limiter.check_at("key-a", t).is_ok());
        assert!(limiter.check_at("key-a", t).is_err());
        assert!(limiter.check_at("key-b", t).is_ok()); // another key has its own counter
    }

    #[test]
    fn test_retry_after_is_the_rest_of_the_window() {
        let limiter = RateLimiter::with_limit(1, Duration::from_secs(60));
        let t = Instant::now();

        assert!(limiter.check_at("key-a", t).is_ok());
        assert_eq!(limiter.check_at("key-a", t + Duration::from_secs(20)), Err(40));
    }

    #[test]
    fn test_zero_limit_turns_rate_limiting_off() {
        let limiter = RateLimiter::with_limit(0, Duration::from_secs(60));
        let t = Instant::now();

        for _ in 0..1000 {
            assert!(limiter.check_at("key-a", t).is_ok());
        }
    }
}
