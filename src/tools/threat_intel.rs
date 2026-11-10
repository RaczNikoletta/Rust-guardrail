use base64::Engine;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use std::env;

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
}

impl ThreatIntel {
    pub fn new() -> Self {
        let api_key = env::var("VIRUSTOTAL_API_KEY").unwrap_or_default();
        let url_regex = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();

        Self { api_key, url_regex }
    }

    /// Extracts all HTTP/HTTPS URLs contained within the prompt.
    pub fn extract_urls(&self, input: &str) -> Vec<String> {
        self.url_regex
            .find_iter(input)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Checks the given URL against the VirusTotal v3 API using unpadded Base64 URL encoding.
    /// Returns `Ok(true)` if the URL is flagged as malicious or suspicious.
    pub fn check_url(&self, target_url: &str) -> Result<bool, String> {
        if self.api_key.is_empty() {
            println!("⚠️ VIRUSTOTAL_API_KEY is not set. Skipping threat check.");
            return Ok(false); // If no API key is set, do not block execution
        }

        // Generate VirusTotal URL identifier (URL-safe Base64 without padding)
        let url_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(target_url.as_bytes());

        let client = reqwest::blocking::Client::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-apikey", HeaderValue::from_str(&self.api_key).unwrap());

        let api_endpoint = format!("https://www.virustotal.com/api/v3/urls/{}", url_id);

        let response = client
            .get(&api_endpoint)
            .headers(headers)
            .send()
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            let vt_res: VtResponse = response.json().map_err(|e| e.to_string())?;
            let stats = vt_res.data.attributes.last_analysis_stats;
            
            // Flagged as threat if at least 1 engine reports malicious or >1 reports suspicious
            let is_threat = stats.malicious > 0 || stats.suspicious > 1;
            Ok(is_threat)
        } else {
            Err(format!("VirusTotal API error: {}", response.status()))
        }
    }
}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls() {
        let intel = ThreatIntel::new();
        let prompt = "Check this site: https://example.com and this one http://test.org/path";
        let urls = intel.extract_urls(prompt);

        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com");
        assert_eq!(urls[1], "http://test.org/path");
    }
}