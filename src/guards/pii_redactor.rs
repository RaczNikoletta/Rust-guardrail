use regex::Regex;

pub struct PiiRedactor {
    email_regex: Regex,
    card_regex: Regex,
    taj_regex: Regex,
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
        }
    }

    /// Redacts sensitive PII data from the given input prompt
    pub fn redact(&self, input: &str) -> String {
        let step1 = self.email_regex.replace_all(input, "[REDACTED_EMAIL]");
        let step2 = self.card_regex.replace_all(&step1, "[REDACTED_CARD]");
        let step3 = self.taj_regex.replace_all(&step2, "[REDACTED_TAJ]");
        step3.to_string()
    }
}