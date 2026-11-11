use base64::Engine;
use regex::Regex;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::{env, time::Duration};

/// At most this many URLs are checked per prompt (the VirusTotal free tier is rate limited).
const MAX_URLS_PER_PROMPT: usize = 3;

/// A VirusTotal request that takes longer than this is abandoned.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

// The structs below describe only the part of the VirusTotal JSON answer that we need:
// { "data": { "attributes": { "last_analysis_stats": { "malicious": 0, "suspicious": 0, ... } } } }
#[derive(Deserialize, Debug)]
struct VtStats {
    malicious: u32,
    suspicious: u32,
}

#[derive(Deserialize, Debug)]
struct VtAttributes {
    last_analysis_stats: VtStats,
}

#[derive(Deserialize, Debug)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize, Debug)]
struct VtResponse {
    data: VtData,
}

pub struct ThreatIntel {
    api_key: String,
    url_regex: Regex,
    // The HTTP client is built once and reused: it keeps connections open between requests.
    client: Client,
}

impl ThreatIntel {
    /// Reads the API key from the `VIRUSTOTAL_API_KEY` environment variable.
    pub fn new() -> Self {
        let api_key = env::var("VIRUSTOTAL_API_KEY").unwrap_or_default();
        if api_key.is_empty() {
            println!("[WARN] VIRUSTOTAL_API_KEY is not set. URL threat checks are disabled.");
        }
        Self::with_api_key(api_key)
    }

    pub fn with_api_key(api_key: String) -> Self {
        let url_regex = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");

        Self {
            api_key,
            url_regex,
            client,
        }
    }

    /// Extracts the HTTP/HTTPS URLs contained within the prompt (at most `MAX_URLS_PER_PROMPT`).
    /// Punctuation that usually follows a URL in a sentence ("... see https://a.com.") is cut off.
    pub fn extract_urls(&self, input: &str) -> Vec<String> {
        self.url_regex
            .find_iter(input)
            .map(|m| {
                m.as_str()
                    .trim_end_matches(|c: char| ".,;:!?)\"'".contains(c))
                    .to_string()
            })
            .take(MAX_URLS_PER_PROMPT)
            .collect()
    }

    /// Checks the given URL against the VirusTotal v3 API using unpadded Base64 URL encoding.
    /// Returns `Ok(true)` if the URL is flagged as malicious or suspicious.
    ///
    /// The function is `async`: while we wait for the network, the server can handle other requests.
    /// Note that the URL is never opened by this program, VirusTotal is only asked about it.
    pub async fn check_url(&self, target_url: &str) -> Result<bool, String> {
        if self.api_key.is_empty() {
            return Ok(false); // If no API key is set, do not block execution
        }

        // Generate VirusTotal URL identifier (URL-safe Base64 without padding)
        let url_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(target_url.as_bytes());
        let api_endpoint = format!("https://www.virustotal.com/api/v3/urls/{}", url_id);

        let response = self
            .client
            .get(&api_endpoint)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        match response.status() {
            StatusCode::OK => {
                let vt_res: VtResponse = response.json().await.map_err(|e| e.to_string())?;
                let stats = vt_res.data.attributes.last_analysis_stats;
                Ok(is_threat(&stats))
            }
            // 404: VirusTotal has never seen this URL, so there is no evidence against it
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(format!("VirusTotal API error: {}", status)),
        }
    }

    /// Checks every URL of the prompt and returns the ones that are flagged as a threat.
    ///
    /// Fail-open: if VirusTotal cannot be reached, the URL is treated as safe and only a warning is printed.
    pub async fn find_malicious_urls(&self, prompt: &str) -> Vec<String> {
        let mut malicious = Vec::new();

        for url in self.extract_urls(prompt) {
            match self.check_url(&url).await {
                Ok(true) => malicious.push(url),
                Ok(false) => {}
                Err(e) => println!("[WARN] VirusTotal check failed: {}", e),
            }
        }

        malicious
    }
}

/// Flagged as threat if at least 1 engine reports malicious or more than 1 reports suspicious.
fn is_threat(stats: &VtStats) -> bool {
    stats.malicious > 0 || stats.suspicious > 1
}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls() {
        let intel = ThreatIntel::with_api_key(String::new());
        let prompt = "Check this site: https://example.com and this one http://test.org/path";
        let urls = intel.extract_urls(prompt);

        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com");
        assert_eq!(urls[1], "http://test.org/path");
    }

    #[test]
    fn test_extract_urls_cuts_trailing_punctuation() {
        let intel = ThreatIntel::with_api_key(String::new());
        let urls = intel.extract_urls("Is it safe (https://example.com/a)? Or https://test.org.");

        assert_eq!(urls, vec!["https://example.com/a", "https://test.org"]);
    }

    #[test]
    fn test_extract_urls_is_limited() {
        let intel = ThreatIntel::with_api_key(String::new());
        let prompt = "https://a.com https://b.com https://c.com https://d.com https://e.com";

        assert_eq!(intel.extract_urls(prompt).len(), MAX_URLS_PER_PROMPT);
    }

    #[test]
    fn test_is_threat_thresholds() {
        assert!(!is_threat(&VtStats { malicious: 0, suspicious: 0 }));
        assert!(!is_threat(&VtStats { malicious: 0, suspicious: 1 }));
        assert!(is_threat(&VtStats { malicious: 0, suspicious: 2 }));
        assert!(is_threat(&VtStats { malicious: 1, suspicious: 0 }));
    }

    #[tokio::test]
    async fn test_without_api_key_nothing_is_blocked() {
        let intel = ThreatIntel::with_api_key(String::new());

        assert_eq!(intel.check_url("http://malware.example").await, Ok(false));
        assert!(intel
            .find_malicious_urls("see http://malware.example")
            .await
            .is_empty());
    }
}
