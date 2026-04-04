extern crate alloc;

use alloc::string::String;
use crate::apps::ecosystem::privacy;
use crate::apps::ecosystem::privacy::stats::{PrivacyStats, get_stats, reset_stats, increment_blocked, increment_params_stripped, increment_fingerprint_blocked, increment_cookies_blocked};
use crate::apps::ecosystem::privacy::tracker_blocker::{is_tracker, should_block, BLOCKED_DOMAINS, blocked_domain_count};
use crate::apps::ecosystem::privacy::url_cleaner::{clean_url, strip_tracking_params, tracking_param_count};

#[test]
fn test_privacy_init() {
    privacy::init();
    let stats = get_stats();
    assert_eq!(stats.requests_blocked, 0);
    assert_eq!(stats.requests_allowed, 0);
}

#[test]
fn test_privacy_start_stop() {
    privacy::start();
    assert!(privacy::is_running());
    privacy::stop();
    assert!(!privacy::is_running());
}

#[test]
fn test_privacy_stats_default() {
    let stats: PrivacyStats = Default::default();
    assert_eq!(stats.requests_blocked, 0);
    assert_eq!(stats.requests_allowed, 0);
    assert_eq!(stats.params_stripped, 0);
    assert_eq!(stats.fingerprint_blocked, 0);
    assert_eq!(stats.cookies_blocked, 0);
}

#[test]
fn test_privacy_stats_total_requests() {
    let stats = PrivacyStats {
        requests_blocked: 10,
        requests_allowed: 90,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    assert_eq!(stats.total_requests(), 100);
}

#[test]
fn test_privacy_stats_block_rate_zero() {
    let stats = PrivacyStats {
        requests_blocked: 0,
        requests_allowed: 0,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    assert_eq!(stats.block_rate(), 0.0);
}

#[test]
fn test_privacy_stats_block_rate_50_percent() {
    let stats = PrivacyStats {
        requests_blocked: 50,
        requests_allowed: 50,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    assert!((stats.block_rate() - 50.0).abs() < 0.01);
}

#[test]
fn test_privacy_stats_block_rate_100_percent() {
    let stats = PrivacyStats {
        requests_blocked: 100,
        requests_allowed: 0,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    assert!((stats.block_rate() - 100.0).abs() < 0.01);
}

#[test]
fn test_reset_stats() {
    reset_stats();
    increment_blocked();
    increment_blocked();
    let stats1 = get_stats();
    assert!(stats1.requests_blocked > 0);
    reset_stats();
    let stats2 = get_stats();
    assert_eq!(stats2.requests_blocked, 0);
}

#[test]
fn test_increment_params_stripped() {
    reset_stats();
    increment_params_stripped();
    increment_params_stripped();
    let stats = get_stats();
    assert_eq!(stats.params_stripped, 2);
    reset_stats();
}

#[test]
fn test_increment_fingerprint_blocked() {
    reset_stats();
    increment_fingerprint_blocked();
    let stats = get_stats();
    assert_eq!(stats.fingerprint_blocked, 1);
    reset_stats();
}

#[test]
fn test_increment_cookies_blocked() {
    reset_stats();
    increment_cookies_blocked();
    increment_cookies_blocked();
    increment_cookies_blocked();
    let stats = get_stats();
    assert_eq!(stats.cookies_blocked, 3);
    reset_stats();
}

#[test]
fn test_is_tracker_exact_match() {
    assert!(is_tracker("google-analytics.com"));
    assert!(is_tracker("doubleclick.net"));
    assert!(is_tracker("facebook.net"));
}

#[test]
fn test_is_tracker_subdomain() {
    assert!(is_tracker("www.google-analytics.com"));
    assert!(is_tracker("sub.doubleclick.net"));
    assert!(is_tracker("cdn.facebook.net"));
}

#[test]
fn test_is_tracker_case_insensitive() {
    assert!(is_tracker("GOOGLE-ANALYTICS.COM"));
    assert!(is_tracker("Google-Analytics.Com"));
}

#[test]
fn test_is_tracker_not_tracker() {
    assert!(!is_tracker("example.com"));
    assert!(!is_tracker("google.com"));
    assert!(!is_tracker("legitimate-site.org"));
}

#[test]
fn test_is_tracker_partial_match_not_blocked() {
    assert!(!is_tracker("notgoogle-analytics.com"));
    assert!(!is_tracker("google-analytics.com.example.org"));
}

#[test]
fn test_blocked_domains_not_empty() {
    assert!(!BLOCKED_DOMAINS.is_empty());
}

#[test]
fn test_blocked_domain_count() {
    assert!(blocked_domain_count() > 50);
}

#[test]
fn test_should_block_tracker_url() {
    reset_stats();
    let (blocked, domain) = should_block("https://google-analytics.com/collect");
    assert!(blocked);
    assert_eq!(domain, Some(String::from("google-analytics.com")));
    reset_stats();
}

#[test]
fn test_should_block_safe_url() {
    reset_stats();
    let (blocked, domain) = should_block("https://example.com/page");
    assert!(!blocked);
    assert_eq!(domain, Some(String::from("example.com")));
    reset_stats();
}

#[test]
fn test_should_block_subdomain_tracker() {
    reset_stats();
    let (blocked, _) = should_block("https://www.doubleclick.net/ad");
    assert!(blocked);
    reset_stats();
}

#[test]
fn test_strip_tracking_params_utm() {
    let url = "https://example.com?utm_source=test&page=1";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com?page=1");
}

#[test]
fn test_strip_tracking_params_fbclid() {
    let url = "https://example.com?fbclid=abc123";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com");
}

#[test]
fn test_strip_tracking_params_gclid() {
    let url = "https://example.com?gclid=xyz&product=shoes";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com?product=shoes");
}

#[test]
fn test_strip_tracking_params_multiple() {
    let url = "https://example.com?utm_source=a&utm_medium=b&id=123";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com?id=123");
}

#[test]
fn test_strip_tracking_params_preserves_fragment() {
    let url = "https://example.com?utm_source=test#section";
    let cleaned = strip_tracking_params(url);
    assert!(cleaned.ends_with("#section"));
}

#[test]
fn test_strip_tracking_params_no_query() {
    let url = "https://example.com/page";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com/page");
}

#[test]
fn test_strip_tracking_params_empty_after_strip() {
    let url = "https://example.com?utm_campaign=x";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com");
}

#[test]
fn test_strip_tracking_params_preserves_legit_params() {
    let url = "https://example.com?page=1&sort=asc&filter=new";
    let cleaned = strip_tracking_params(url);
    assert_eq!(cleaned, "https://example.com?page=1&sort=asc&filter=new");
}

#[test]
fn test_clean_url_decodes_amp() {
    let url = "https://example.com?utm_source=test&amp;page=1";
    let cleaned = clean_url(url);
    assert_eq!(cleaned, "https://example.com?page=1");
}

#[test]
fn test_clean_url_removes_trailing_question_mark() {
    let url = "https://example.com?utm_source=only";
    let cleaned = clean_url(url);
    assert!(!cleaned.ends_with('?'));
}

#[test]
fn test_tracking_param_count_positive() {
    assert!(tracking_param_count() > 50);
}

#[test]
fn test_strip_all_utm_variants() {
    let variants = [
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_cid", "utm_reader", "utm_name", "utm_social",
    ];
    for param in variants {
        let url = alloc::format!("https://example.com?{}=value&keep=this", param);
        let cleaned = strip_tracking_params(&url);
        assert!(!cleaned.contains(param));
        assert!(cleaned.contains("keep=this"));
    }
}

#[test]
fn test_strip_social_trackers() {
    let trackers = ["fbclid", "gclid", "twclid", "igshid", "msclkid"];
    for param in trackers {
        let url = alloc::format!("https://example.com?{}=abc123", param);
        let cleaned = strip_tracking_params(&url);
        assert!(!cleaned.contains(param));
    }
}

#[test]
fn test_strip_analytics_params() {
    let params = ["_ga", "_gl", "__hssc", "__hstc"];
    for param in params {
        let url = alloc::format!("https://example.com?{}=value&valid=true", param);
        let cleaned = strip_tracking_params(&url);
        assert!(!cleaned.contains(param));
    }
}

#[test]
fn test_blocked_domains_contains_major_trackers() {
    let major_trackers = [
        "google-analytics.com",
        "doubleclick.net",
        "facebook.net",
        "hotjar.com",
        "mixpanel.com",
    ];
    for tracker in major_trackers {
        assert!(BLOCKED_DOMAINS.contains(&tracker), "Missing: {}", tracker);
    }
}

#[test]
fn test_url_with_only_tracking_params() {
    let url = "https://example.com?utm_source=email&utm_medium=cpc&fbclid=123";
    let cleaned = clean_url(url);
    assert_eq!(cleaned, "https://example.com");
}

#[test]
fn test_mixed_case_tracking_params() {
    let url = "https://example.com?UTM_SOURCE=test&page=1";
    let cleaned = strip_tracking_params(url);
    assert!(!cleaned.to_lowercase().contains("utm_source"));
}
