use regex::{Captures, Regex};

/// Luhn checksum: real card numbers pass it, random digit strings (order numbers, IDs) mostly do not.
fn luhn_valid(digits: &str) -> bool {
    let digits: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=16).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Hungarian TAJ checksum: digits 1-8 are weighted 3,7,3,7,... and the sum mod 10 must equal digit 9.
fn taj_valid(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 9 {
        return false;
    }
    let sum: u32 = d[..8]
        .iter()
        .enumerate()
        .map(|(i, &x)| x * if i % 2 == 0 { 3 } else { 7 })
        .sum();
    sum % 10 == d[8]
}

pub struct PiiRedactor {
    email_regex: Regex,
    card_regex: Regex,
    taj_regex: Regex,
    api_key_regex: Regex,
}

impl PiiRedactor {
    pub fn new() -> Self {
        Self {
            // Pattern for standard email addresses
            email_regex: Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap(),
            // Pattern for credit card numbers (16 digits with spaces or hyphens)
            card_regex: Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap(),
            // Pattern for Hungarian TAJ (SSN) numbers (9 digits: 123 456 789 or 123456789)
            taj_regex: Regex::new(r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b").unwrap(),
            // OpenAI (sk-..., sk-proj-...), GitHub (ghp_...), Slack (xoxb-...) and Bearer tokens.
            // No trailing \b: it would fail after a '=' or '-' at the end of a token.
            api_key_regex: Regex::new(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xoxb-[0-9]{10,13}-[A-Za-z0-9]{24})|(?i:bearer)\s+[A-Za-z0-9\-._~+/]+=*").unwrap(),
        }
    }

    /// Redacts sensitive PII data from the given input prompt
    pub fn redact(&self, input: &str) -> String {
        // Keys go first: a long key could otherwise be partly eaten by the card/TAJ patterns.
        let text = self.api_key_regex.replace_all(input, "[REDACTED_API_KEY]");
        let text = self.email_regex.replace_all(&text, "[REDACTED_EMAIL]");
        // Cards and TAJ numbers are only redacted if the checksum is valid (fewer false positives).
        let text = self.card_regex.replace_all(&text, |caps: &Captures| {
            if luhn_valid(&caps[0]) { "[REDACTED_CARD]".to_string() } else { caps[0].to_string() }
        });
        let text = self.taj_regex.replace_all(&text, |caps: &Captures| {
            if taj_valid(&caps[0]) { "[REDACTED_TAJ]".to_string() } else { caps[0].to_string() }
        });
        text.into_owned()
    }
}
// --- PII redactor test

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let redactor = PiiRedactor::new();
        let input = "Contact me at user@example.com for details.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "Contact me at [REDACTED_EMAIL] for details.");
    }

    #[test]
    fn test_taj_number_redaction() {
        let redactor = PiiRedactor::new();
        let input = "My TAJ number is 123-456-788.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "My TAJ number is [REDACTED_TAJ].");
    }

    #[test]
    fn test_invalid_taj_is_not_redacted() {
        let redactor = PiiRedactor::new();
        let input = "Order number 123-456-789.";

        assert_eq!(redactor.redact(input), input);
    }

    #[test]
    fn test_credit_card_redaction() {
        let redactor = PiiRedactor::new();
        let input = "Card number: 4111 1111 1111 1111.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "Card number: [REDACTED_CARD].");
    }

    #[test]
    fn test_multiple_pii_in_one_prompt() {
        let redactor = PiiRedactor::new();
        let input = "Email: test@example.com, Card: 4111-1111-1111-1111, TAJ: 123 456 788";
        let redacted = redactor.redact(input);
        
        assert_eq!(
            redacted, 
            "Email: [REDACTED_EMAIL], Card: [REDACTED_CARD], TAJ: [REDACTED_TAJ]"
        );
    }

    #[test]
    fn test_clean_prompt_remains_unchanged() {
        let redactor = PiiRedactor::new();
        let input = "Write a Rust program to calculate Fibonacci numbers.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, input);
    }

    #[test]
    fn test_api_key_redaction() {
        let redactor = PiiRedactor::new();
        let input = "Here is my key: ghp_1234567890abcdefghijklmnopqrstuvwxyz and test again.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "Here is my key: [REDACTED_API_KEY] and test again.");
    }

    #[test]
    fn test_openai_project_key_redaction() {
        let redactor = PiiRedactor::new();
        let input = "key=sk-proj-abcdefghijklmnopqrstuvwxyz_0123456789-AB end";

        assert_eq!(redactor.redact(input), "key=[REDACTED_API_KEY] end");
    }
}
