extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

pub struct HstsEntry {
    pub host: String,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub created_at: u64,
}

pub struct HstsCache {
    entries: Vec<HstsEntry>,
}

impl HstsCache {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn parse_and_store(&mut self, host: &str, header: &str, now: u64) {
        let mut max_age = 0u64;
        let mut include_subdomains = false;
        for directive in header.split(';') {
            let d = directive.trim();
            if d.starts_with("max-age=") || d.starts_with("Max-Age=") {
                max_age = d[8..].trim().parse().unwrap_or(0);
            }
            if d.eq_ignore_ascii_case("includeSubDomains") {
                include_subdomains = true;
            }
        }
        self.entries.retain(|e| e.host != host);
        if max_age > 0 {
            self.entries.push(HstsEntry { host: String::from(host), max_age, include_subdomains, created_at: now });
        }
    }

    pub fn should_upgrade(&self, host: &str, now: u64) -> bool {
        for entry in &self.entries {
            if now > entry.created_at + entry.max_age { continue; }
            if entry.host == host { return true; }
            if entry.include_subdomains && host.ends_with(&alloc::format!(".{}", entry.host)) { return true; }
        }
        false
    }

    pub fn upgrade_url(&self, url: &str, now: u64) -> String {
        if !url.starts_with("http://") { return String::from(url); }
        let host_start = 7;
        let host_end = url[host_start..].find('/').map(|i| i + host_start).unwrap_or(url.len());
        let host_port = &url[host_start..host_end];
        let host = host_port.split(':').next().unwrap_or(host_port);
        if self.should_upgrade(host, now) {
            let mut upgraded = String::from("https://");
            upgraded.push_str(&url[host_start..]);
            upgraded
        } else { String::from(url) }
    }

    pub fn cleanup_expired(&mut self, now: u64) {
        self.entries.retain(|e| now <= e.created_at + e.max_age);
    }
}
