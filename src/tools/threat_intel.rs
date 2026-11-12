use base64::Engine;
use regex::Regex;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::{env, net::Ipv4Addr, time::Duration};

/// At most this many URLs are checked per prompt (the VirusTotal free tier is rate limited).
const MAX_URLS_PER_PROMPT: usize = 3;

/// Same limit for IP addresses.
const MAX_IPS_PER_PROMPT: usize = 3;

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
    ip_regex: Regex,
    // The HTTP client is built once and reused: it keeps connections open between requests.
    client: Client,
}

impl ThreatIntel {
    /// Reads the API key from the `VIRUSTOTAL_API_KEY` environment variable.
    pub fn new() -> Self {
        let api_key = env::var("VIRUSTOTAL_API_KEY").unwrap_or_default();
        if api_key.is_empty() {
            println!("[WARN] VIRUSTOTAL_API_KEY is not set. URL and IP threat checks are disabled.");
        }
        Self::with_api_key(api_key)
    }

    pub fn with_api_key(api_key: String) -> Self {
        let url_regex = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();
        // Only a rough candidate filter: the real validation is done by `Ipv4Addr::parse`.
        let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("failed to build HTTP client");

        Self {
            api_key,
            url_regex,
            ip_regex,
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

    /// Extracts the public IPv4 addresses of the prompt (at most `MAX_IPS_PER_PROMPT`, no duplicates).
    ///
    /// - Text that is part of a URL is ignored here: `check_url` already covers it.
    /// - Every candidate is parsed with `Ipv4Addr`, so only valid addresses survive
    ///   ("999.1.1.1" is dropped) and nothing but digits and dots is ever put into the API path.
    /// - Private, loopback and other non-public addresses are skipped: VirusTotal knows nothing
    ///   about them, and sending them would leak details of an internal network.
    pub fn extract_ips(&self, input: &str) -> Vec<String> {
        let without_urls = self.url_regex.replace_all(input, " ");
        let mut ips: Vec<String> = Vec::new();

        for candidate in self.ip_regex.find_iter(&without_urls) {
            if ips.len() == MAX_IPS_PER_PROMPT {
                break;
            }
            if let Ok(ip) = candidate.as_str().parse::<Ipv4Addr>() {
                let ip_text = ip.to_string();
                if is_public(&ip) && !ips.contains(&ip_text) {
                    ips.push(ip_text);
                }
            }
        }
        ips
    }

    /// Checks the given URL against the VirusTotal v3 API using unpadded Base64 URL encoding.
    /// Returns `Ok(true)` if the URL is flagged as malicious or suspicious.
    ///
    /// The function is `async`: while we wait for the network, the server can handle other requests.
    /// Note that the URL is never opened by this program, VirusTotal is only asked about it.
    pub async fn check_url(&self, target_url: &str) -> Result<bool, String> {
        // Generate VirusTotal URL identifier (URL-safe Base64 without padding)
        let url_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(target_url.as_bytes());
        self.lookup(&format!("https://www.virustotal.com/api/v3/urls/{}", url_id))
            .await
    }

    /// Checks the given IP address against the VirusTotal v3 API.
    /// Returns `Ok(true)` if the IP is flagged as malicious or suspicious.
    /// `ip` must come from `extract_ips` (an already validated address).
    pub async fn check_ip(&self, ip: &str) -> Result<bool, String> {
        self.lookup(&format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip))
            .await
    }

    /// Shared part of the URL and IP checks: asks VirusTotal and reads the analysis stats.
    async fn lookup(&self, api_endpoint: &str) -> Result<bool, String> {
        if self.api_key.is_empty() {
            return Ok(false); // If no API key is set, do not block execution
        }

        let response = self
            .client
            .get(api_endpoint)
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
            // 404: VirusTotal has never seen this URL or IP, so there is no evidence against it
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

    /// Checks every IP address of the prompt and returns the ones that are flagged as a threat.
    /// Fail-open, like `find_malicious_urls`.
    pub async fn find_malicious_ips(&self, prompt: &str) -> Vec<String> {
        let mut malicious = Vec::new();

        for ip in self.extract_ips(prompt) {
            match self.check_ip(&ip).await {
                Ok(true) => malicious.push(ip),
                Ok(false) => {}
                Err(e) => println!("[WARN] VirusTotal IP check failed: {}", e),
            }
        }

        malicious
    }
}

/// Only addresses that exist on the public internet are worth asking VirusTotal about.
fn is_public(ip: &Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation())
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

    #[test]
    fn test_extract_ips() {
        let intel = ThreatIntel::with_api_key(String::new());
        let ips = intel.extract_ips("Is 8.8.8.8 or 1.1.1.1 safe? Also 8.8.8.8 again.");

        assert_eq!(ips, vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[test]
    fn test_extract_ips_skips_invalid_and_non_public() {
        let intel = ThreatIntel::with_api_key(String::new());
        let prompt = "999.1.1.1 192.168.1.10 10.0.0.1 127.0.0.1 169.254.1.1 0.0.0.0 203.0.113.5";

        assert!(intel.extract_ips(prompt).is_empty());
    }

    #[test]
    fn test_extract_ips_ignores_ips_inside_urls() {
        let intel = ThreatIntel::with_api_key(String::new());
        let ips = intel.extract_ips("see http://8.8.4.4/path and 1.1.1.1");

        assert_eq!(ips, vec!["1.1.1.1"]);
    }

    #[test]
    fn test_extract_ips_is_limited() {
        let intel = ThreatIntel::with_api_key(String::new());
        let ips = intel.extract_ips("8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9");

        assert_eq!(ips.len(), MAX_IPS_PER_PROMPT);
    }

    #[tokio::test]
    async fn test_without_api_key_nothing_is_blocked() {
        let intel = ThreatIntel::with_api_key(String::new());

        assert_eq!(intel.check_url("http://malware.example").await, Ok(false));
        assert_eq!(intel.check_ip("8.8.8.8").await, Ok(false));
        assert!(intel
            .find_malicious_urls("see http://malware.example")
            .await
            .is_empty());
        assert!(intel.find_malicious_ips("see 8.8.8.8").await.is_empty());
    }
}
