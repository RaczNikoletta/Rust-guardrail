use regex::Regex;

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
            // OpenAI (sk-...), Generic Bearer, GitHub (ghp_...), Slack (xoxb-...) tokens
            api_key_regex: Regex::new(r"(?i)\b(sk-[a-zA-Z0-9T3BlbkFJ]{20,}|ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]{10,13}-[a-zA-Z0-9]{24}|Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*)\b").unwrap(),
        }
    }

    /// Redacts sensitive PII data from the given input prompt
    pub fn redact(&self, input: &str) -> String {
        let step1 = self.email_regex.replace_all(input, "[REDACTED_EMAIL]");
        let step2 = self.card_regex.replace_all(&step1, "[REDACTED_CARD]");
        let step3 = self.taj_regex.replace_all(&step2, "[REDACTED_TAJ]");
        let step4 = self.api_key_regex.replace_all(&step3, "[REDACTED_API_KEY]");
        step4.to_string()
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
        let input = "My TAJ number is 123-456-789.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "My TAJ number is [REDACTED_TAJ].");
    }

    #[test]
    fn test_credit_card_redaction() {
        let redactor = PiiRedactor::new();
        let input = "Card number: 4532 0150 1234 5678.";
        let redacted = redactor.redact(input);
        
        assert_eq!(redacted, "Card number: [REDACTED_CARD].");
    }

    #[test]
    fn test_multiple_pii_in_one_prompt() {
        let redactor = PiiRedactor::new();
        let input = "Email: test@example.com, Card: 4532-0150-1234-5678, TAJ: 123 456 789";
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
}