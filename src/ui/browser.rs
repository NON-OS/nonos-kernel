use crate::security::data_leak_detection::{monitor_network_data, DataLeakEvent};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

pub struct BrowserEngine {
    tabs: Vec<BrowserTab>,
    active_tab: usize,
    security_policy: SecurityPolicy,
    history: Vec<HistoryEntry>,
    cookies: BTreeMap<String, Cookie>,
    cache: Vec<CacheEntry>,
    downloads: Vec<Download>,
}

#[derive(Clone)]
pub struct BrowserTab {
    id: u32,
    url: String,
    title: String,
    content: Vec<u8>,
    status: TabStatus,
    security_level: SecurityLevel,
    last_activity: u64,
    javascript_enabled: bool,
    cookies_enabled: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum TabStatus {
    Loading = 1,
    Loaded = 2,
    Error = 3,
    Blocked = 4,
    Redirecting = 5,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum SecurityLevel {
    Insecure = 0,
    Mixed = 1,
    Secure = 2,
    ExtendedValidation = 3,
    Enhanced = 4,
    Maximum = 5,
}

pub struct SecurityPolicy {
    blocked_domains: Vec<String>,
    allowed_domains: Vec<String>,
    javascript_policy: JavaScriptPolicy,
    cookie_policy: CookiePolicy,
    download_policy: DownloadPolicy,
    content_filtering: ContentFiltering,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum JavaScriptPolicy {
    Blocked = 0,
    AllowedSafe = 1,
    AllowedAll = 2,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CookiePolicy {
    Blocked = 0,
    FirstPartyOnly = 1,
    AllowedAll = 2,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DownloadPolicy {
    Blocked = 0,
    ScanFirst = 1,
    AllowedAll = 2,
}

pub struct ContentFiltering {
    block_malware: bool,
    block_phishing: bool,
    block_adult_content: bool,
    block_tracking: bool,
    block_ads: bool,
}

#[derive(Clone)]
pub struct HistoryEntry {
    url: String,
    title: String,
    timestamp: u64,
    visit_count: u32,
}

#[derive(Clone)]
pub struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    expires: u64,
    secure: bool,
    http_only: bool,
    same_site: SameSitePolicy,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SameSitePolicy {
    None = 0,
    Lax = 1,
    Strict = 2,
}

#[derive(Clone)]
pub struct CacheEntry {
    url: String,
    content: Vec<u8>,
    content_type: String,
    timestamp: u64,
    etag: String,
    expires: u64,
}

#[derive(Clone)]
pub struct Download {
    id: u32,
    url: String,
    filename: String,
    size: usize,
    downloaded: usize,
    status: DownloadStatus,
    started: u64,
    security_scan_result: ScanResult,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum DownloadStatus {
    Queued = 1,
    Downloading = 2,
    Paused = 3,
    Completed = 4,
    Failed = 5,
    Cancelled = 6,
    Scanning = 7,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum ScanResult {
    NotScanned = 0,
    Clean = 1,
    Suspicious = 2,
    Malware = 3,
    Blocked = 4,
}

pub struct NetworkMonitor {
    requests: Vec<NetworkRequest>,
    blocked_requests: Vec<BlockedRequest>,
    data_usage: DataUsage,
}

#[derive(Clone)]
pub struct NetworkRequest {
    url: String,
    method: HttpMethod,
    size: usize,
    timestamp: u64,
    response_code: u16,
    security_flags: u32,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum HttpMethod {
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
    Patch = 7,
}

#[derive(Clone)]
pub struct BlockedRequest {
    url: String,
    reason: BlockReason,
    timestamp: u64,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum BlockReason {
    BlacklistedDomain = 1,
    Malware = 2,
    Phishing = 3,
    AdultContent = 4,
    Tracking = 5,
    Advertisement = 6,
    DataLeak = 7,
    SecurityPolicy = 8,
}

pub struct DataUsage {
    bytes_sent: u64,
    bytes_received: u64,
    requests_sent: u64,
    requests_blocked: u64,
}

impl BrowserEngine {
    pub fn new() -> Self {
        BrowserEngine {
            tabs: Vec::new(),
            active_tab: 0,
            security_policy: SecurityPolicy::new(),
            history: Vec::new(),
            cookies: BTreeMap::new(),
            cache: Vec::new(),
            downloads: Vec::new(),
        }
    }

    pub fn create_tab(&mut self, url: String) -> Result<u32, &'static str> {
        let tab_id = self.tabs.len() as u32;

        if !self.security_policy.is_url_allowed(&url) {
            return Err("URL blocked by security policy");
        }

        let tab = BrowserTab {
            id: tab_id,
            url: url.clone(),
            title: "Loading...".into(),
            content: Vec::new(),
            status: TabStatus::Loading,
            security_level: SecurityLevel::Insecure,
            last_activity: crate::time::get_timestamp(),
            javascript_enabled: matches!(
                self.security_policy.javascript_policy,
                JavaScriptPolicy::AllowedAll | JavaScriptPolicy::AllowedSafe
            ),
            cookies_enabled: !matches!(self.security_policy.cookie_policy, CookiePolicy::Blocked),
        };

        self.tabs.push(tab);
        self.active_tab = tab_id as usize;

        Ok(tab_id)
    }

    pub fn navigate_to(&mut self, tab_id: u32, url: String) -> Result<(), &'static str> {
        let tab_index = self.find_tab_index(tab_id)?;

        if !self.security_policy.is_url_allowed(&url) {
            self.tabs[tab_index].status = TabStatus::Blocked;
            return Err("URL blocked by security policy");
        }

        if self.security_policy.content_filtering.block_phishing && self.is_phishing_url(&url) {
            self.tabs[tab_index].status = TabStatus::Blocked;
            return Err("Phishing URL detected");
        }

        if self.security_policy.content_filtering.block_malware && self.is_malware_url(&url) {
            self.tabs[tab_index].status = TabStatus::Blocked;
            return Err("Malware URL detected");
        }

        self.tabs[tab_index].url = url.clone();
        self.tabs[tab_index].status = TabStatus::Loading;
        self.tabs[tab_index].last_activity = crate::time::get_timestamp();

        self.add_to_history(url.clone(), "".into());

        Ok(())
    }

    fn find_tab_index(&self, tab_id: u32) -> Result<usize, &'static str> {
        self.tabs.iter().position(|tab| tab.id == tab_id).ok_or("Tab not found")
    }

    fn is_phishing_url(&self, url: &str) -> bool {
        let phishing_indicators = [
            "phishing",
            "fake",
            "scam",
            "malicious",
            "suspicious",
            "payp4l",
            "g00gle",
            "microsofft",
            "amazom",
        ];

        for indicator in &phishing_indicators {
            if url.to_lowercase().contains(indicator) {
                return true;
            }
        }

        false
    }

    fn is_malware_url(&self, url: &str) -> bool {
        let malware_extensions = [".exe", ".bat", ".scr", ".pif", ".com", ".vbs", ".jar"];

        for ext in &malware_extensions {
            if url.to_lowercase().ends_with(ext) {
                return true;
            }
        }

        false
    }

    pub fn load_content(
        &mut self,
        tab_id: u32,
        content: Vec<u8>,
        content_type: String,
    ) -> Result<(), &'static str> {
        let tab_index = self.find_tab_index(tab_id)?;

        if self.security_policy.content_filtering.block_malware
            && self.scan_content_for_malware(&content)
        {
            self.tabs[tab_index].status = TabStatus::Blocked;
            return Err("Malicious content detected");
        }

        if let Some(_leak_event) = monitor_network_data(&content, [0, 0, 0, 0], 80) {
            return Err("Potential data leak detected");
        }

        self.tabs[tab_index].content = content;
        self.tabs[tab_index].status = TabStatus::Loaded;
        self.tabs[tab_index].last_activity = crate::time::get_timestamp();

        self.update_security_level(tab_index);

        // Clone values to avoid borrow conflicts
        let tab_url = self.tabs[tab_index].url.clone();
        let tab_content = self.tabs[tab_index].content.clone();
        self.cache_content(&tab_url, &tab_content, content_type);

        Ok(())
    }

    fn scan_content_for_malware(&self, content: &[u8]) -> bool {
        let malware_signatures: &[&[u8]] = &[
            b"<script>alert('XSS')</script>",
            b"javascript:void(0)",
            b"eval(",
            b"document.cookie",
            b"XMLHttpRequest",
        ];

        for signature in malware_signatures {
            if self.boyer_moore_search(content, signature) {
                return true;
            }
        }

        false
    }

    fn boyer_moore_search(&self, text: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || text.len() < pattern.len() {
            return false;
        }

        let mut bad_char_table = [pattern.len(); 256];
        for (i, &byte) in pattern.iter().enumerate() {
            if i < pattern.len() - 1 {
                bad_char_table[byte as usize] = pattern.len() - 1 - i;
            }
        }

        let mut i = 0;
        while i <= text.len() - pattern.len() {
            let mut j = pattern.len();
            while j > 0 && pattern[j - 1] == text[i + j - 1] {
                j -= 1;
            }

            if j == 0 {
                return true;
            }

            let bad_char_skip =
                if i + j < text.len() { bad_char_table[text[i + j] as usize] } else { 1 };

            i += bad_char_skip.max(1);
        }

        false
    }

    fn update_security_level(&mut self, tab_index: usize) {
        let url = &self.tabs[tab_index].url;

        if url.starts_with("https://") {
            self.tabs[tab_index].security_level = SecurityLevel::Secure;
        } else if url.starts_with("http://") {
            self.tabs[tab_index].security_level = SecurityLevel::Insecure;
        } else {
            self.tabs[tab_index].security_level = SecurityLevel::Mixed;
        }
    }

    fn cache_content(&mut self, url: &str, content: &[u8], content_type: String) {
        let cache_entry = CacheEntry {
            url: url.into(),
            content: content.to_vec(),
            content_type,
            timestamp: crate::time::get_timestamp(),
            etag: format!("{:x}", self.simple_hash(content)),
            expires: crate::time::get_timestamp() + 3600,
        };

        self.cache.push(cache_entry);

        if self.cache.len() > 1000 {
            self.cache.remove(0);
        }
    }

    fn simple_hash(&self, data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for &byte in data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    fn add_to_history(&mut self, url: String, title: String) {
        if let Some(entry) = self.history.iter_mut().find(|e| e.url == url) {
            entry.visit_count += 1;
            entry.timestamp = crate::time::get_timestamp();
        } else {
            let entry = HistoryEntry {
                url,
                title,
                timestamp: crate::time::get_timestamp(),
                visit_count: 1,
            };
            self.history.push(entry);
        }

        if self.history.len() > 10000 {
            self.history.remove(0);
        }
    }

    pub fn close_tab(&mut self, tab_id: u32) -> Result<(), &'static str> {
        let tab_index = self.find_tab_index(tab_id)?;
        self.tabs.remove(tab_index);

        if self.tabs.is_empty() {
            self.active_tab = 0;
        } else if self.active_tab >= self.tabs.len() {
            self.active_tab = self.tabs.len() - 1;
        }

        Ok(())
    }

    pub fn get_active_tab(&self) -> Option<&BrowserTab> {
        if self.active_tab < self.tabs.len() {
            Some(&self.tabs[self.active_tab])
        } else {
            None
        }
    }

    pub fn set_cookie(
        &mut self,
        domain: String,
        name: String,
        value: String,
        expires: u64,
    ) -> Result<(), &'static str> {
        if matches!(self.security_policy.cookie_policy, CookiePolicy::Blocked) {
            return Err("Cookies are blocked");
        }

        let cookie = Cookie {
            name: name.clone(),
            value,
            domain: domain.clone(),
            path: "/".into(),
            expires,
            secure: false,
            http_only: false,
            same_site: SameSitePolicy::Lax,
        };

        let key = format!("{}:{}", domain, name);
        self.cookies.insert(key, cookie);

        Ok(())
    }

    pub fn get_cookies_for_domain(&self, domain: &str) -> Vec<&Cookie> {
        self.cookies
            .values()
            .filter(|cookie| cookie.domain == domain || domain.ends_with(&cookie.domain))
            .collect()
    }

    pub fn start_download(&mut self, url: String, filename: String) -> Result<u32, &'static str> {
        if matches!(self.security_policy.download_policy, DownloadPolicy::Blocked) {
            return Err("Downloads are blocked");
        }

        let download_id = self.downloads.len() as u32;

        let download = Download {
            id: download_id,
            url,
            filename,
            size: 0,
            downloaded: 0,
            status: DownloadStatus::Queued,
            started: crate::time::get_timestamp(),
            security_scan_result: ScanResult::NotScanned,
        };

        self.downloads.push(download);
        Ok(download_id)
    }

    pub fn get_browser_statistics(&self) -> BrowserStatistics {
        BrowserStatistics {
            active_tabs: self.tabs.len(),
            history_entries: self.history.len(),
            cached_items: self.cache.len(),
            stored_cookies: self.cookies.len(),
            active_downloads: self
                .downloads
                .iter()
                .filter(|d| {
                    matches!(d.status, DownloadStatus::Downloading | DownloadStatus::Queued)
                })
                .count(),
            completed_downloads: self
                .downloads
                .iter()
                .filter(|d| matches!(d.status, DownloadStatus::Completed))
                .count(),
            fingerprinting_blocked: 0, // TODO: Track actual fingerprinting attempts blocked
        }
    }
}

pub struct BrowserStatistics {
    pub active_tabs: usize,
    pub history_entries: usize,
    pub cached_items: usize,
    pub stored_cookies: usize,
    pub active_downloads: usize,
    pub completed_downloads: usize,
    pub fingerprinting_blocked: usize,
}

impl SecurityPolicy {
    pub fn new() -> Self {
        SecurityPolicy {
            blocked_domains: Vec::new(),
            allowed_domains: Vec::new(),
            javascript_policy: JavaScriptPolicy::AllowedSafe,
            cookie_policy: CookiePolicy::FirstPartyOnly,
            download_policy: DownloadPolicy::ScanFirst,
            content_filtering: ContentFiltering {
                block_malware: true,
                block_phishing: true,
                block_adult_content: false,
                block_tracking: true,
                block_ads: false,
            },
        }
    }

    pub fn is_url_allowed(&self, url: &str) -> bool {
        if self.allowed_domains.is_empty() {
            !self.is_domain_blocked(url)
        } else {
            self.is_domain_allowed(url) && !self.is_domain_blocked(url)
        }
    }

    fn is_domain_blocked(&self, url: &str) -> bool {
        for domain in &self.blocked_domains {
            if url.contains(domain) {
                return true;
            }
        }
        false
    }

    fn is_domain_allowed(&self, url: &str) -> bool {
        for domain in &self.allowed_domains {
            if url.contains(domain) {
                return true;
            }
        }
        false
    }

    pub fn block_domain(&mut self, domain: String) {
        if !self.blocked_domains.contains(&domain) {
            self.blocked_domains.push(domain);
        }
    }

    pub fn allow_domain(&mut self, domain: String) {
        if !self.allowed_domains.contains(&domain) {
            self.allowed_domains.push(domain);
        }
    }

    pub fn set_javascript_policy(&mut self, policy: JavaScriptPolicy) {
        self.javascript_policy = policy;
    }

    pub fn set_cookie_policy(&mut self, policy: CookiePolicy) {
        self.cookie_policy = policy;
    }

    pub fn set_download_policy(&mut self, policy: DownloadPolicy) {
        self.download_policy = policy;
    }
}

static mut BROWSER_ENGINE: Option<BrowserEngine> = None;
static mut NETWORK_MONITOR: Option<NetworkMonitor> = None;

pub fn init_browser() {
    unsafe {
        BROWSER_ENGINE = Some(BrowserEngine::new());
        NETWORK_MONITOR = Some(NetworkMonitor {
            requests: Vec::new(),
            blocked_requests: Vec::new(),
            data_usage: DataUsage {
                bytes_sent: 0,
                bytes_received: 0,
                requests_sent: 0,
                requests_blocked: 0,
            },
        });
    }
}

pub fn create_browser_tab(url: String) -> Result<u32, &'static str> {
    unsafe {
        if let Some(ref mut browser) = BROWSER_ENGINE {
            browser.create_tab(url)
        } else {
            Err("Browser engine not initialized")
        }
    }
}

pub fn navigate_browser_tab(tab_id: u32, url: String) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref mut browser) = BROWSER_ENGINE {
            browser.navigate_to(tab_id, url)
        } else {
            Err("Browser engine not initialized")
        }
    }
}

pub fn close_browser_tab(tab_id: u32) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref mut browser) = BROWSER_ENGINE {
            browser.close_tab(tab_id)
        } else {
            Err("Browser engine not initialized")
        }
    }
}

pub fn get_browser_stats() -> Option<BrowserStatistics> {
    unsafe { BROWSER_ENGINE.as_ref().map(|b| b.get_browser_statistics()) }
}

/// Detect fingerprinting attempts by websites
pub fn detect_fingerprinting_attempts() -> bool {
    unsafe {
        if let Some(ref browser) = BROWSER_ENGINE {
            browser.get_browser_statistics().fingerprinting_blocked > 0
        } else {
            false
        }
    }
}
