use crate::guards::normalize::normalize;
use rand::{distributions::Alphanumeric, Rng};

/// Length of the random part of the canary. 24 random letters/digits cannot be guessed
/// and cannot appear in a normal answer by accident.
const CANARY_RANDOM_LEN: usize = 24;

/// Output guard: hides a secret "canary" in the instructions given to the model.
/// The canary is never needed in a legitimate answer, so if it shows up in the answer,
/// the model has leaked its instructions (typically after a successful prompt injection).
pub struct OutputCanaryGuard {
    canary: String,
}

impl OutputCanaryGuard {
    /// Creates a new random canary. It changes every time the proxy starts.
    pub fn new() -> Self {
        let random: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(CANARY_RANDOM_LEN)
            .map(char::from)
            .collect();

        Self { canary: format!("GR{}", random) }
    }

    /// The canary text. It goes into the system instruction, never into a response or a log.
    pub fn canary(&self) -> &str {
        &self.canary
    }

    /// `true` if the model's answer contains the canary.
    ///
    /// The answer is normalized first (invisible characters removed). Then only letters and
    /// digits are compared, ignoring case, so `gr-AB cd...` or a canary with zero-width
    /// characters inside is found too.
    pub fn leaks(&self, answer: &str) -> bool {
        let cleaned = squash(&normalize(answer));
        cleaned.contains(&squash(&self.canary))
    }
}

/// Keeps only letters and digits, lowercased.
fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_has_expected_length_and_is_random() {
        let a = OutputCanaryGuard::new();
        let b = OutputCanaryGuard::new();

        assert_eq!(a.canary().len(), 2 + CANARY_RANDOM_LEN);
        assert_ne!(a.canary(), b.canary());
    }

    #[test]
    fn test_plain_leak_is_detected() {
        let guard = OutputCanaryGuard::new();
        let answer = format!("My code is {}", guard.canary());

        assert!(guard.leaks(&answer));
    }

    #[test]
    fn test_case_and_separators_do_not_hide_the_canary() {
        let guard = OutputCanaryGuard::new();
        let spaced: String = guard
            .canary()
            .to_lowercase()
            .chars()
            .flat_map(|c| [c, '-'])
            .collect();

        assert!(guard.leaks(&spaced));
    }

    #[test]
    fn test_zero_width_characters_do_not_hide_the_canary() {
        let guard = OutputCanaryGuard::new();
        let sneaky: String = guard
            .canary()
            .chars()
            .flat_map(|c| [c, '\u{200B}'])
            .collect();

        assert!(guard.leaks(&sneaky));
    }

    #[test]
    fn test_normal_answer_is_not_flagged() {
        let guard = OutputCanaryGuard::new();

        assert!(!guard.leaks("Rust is a systems programming language."));
        assert!(!guard.leaks(""));
    }

    #[test]
    fn test_canary_of_another_run_is_not_flagged() {
        let guard = OutputCanaryGuard::new();
        let other = OutputCanaryGuard::new();

        assert!(!guard.leaks(other.canary()));
    }
}
