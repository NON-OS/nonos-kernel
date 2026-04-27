// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::privacy;
use crate::apps::ecosystem::privacy::stats::{
    get_stats, increment_blocked, increment_cookies_blocked, increment_fingerprint_blocked,
    increment_params_stripped, reset_stats, PrivacyStats,
};
use crate::apps::ecosystem::privacy::tracker_blocker::{
    blocked_domain_count, is_tracker, should_block, BLOCKED_DOMAINS,
};
use crate::apps::ecosystem::privacy::url_cleaner::{
    clean_url, strip_tracking_params, tracking_param_count,
};
use crate::test::framework::TestResult;

pub(crate) fn test_privacy_init() -> TestResult {
    privacy::init();
    let stats = get_stats();
    if stats.requests_blocked != 0 {
        return TestResult::Fail;
    }
    if stats.requests_allowed != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_start_stop() -> TestResult {
    privacy::start();
    if !privacy::is_running() {
        return TestResult::Fail;
    }
    privacy::stop();
    if privacy::is_running() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_stats_default() -> TestResult {
    let stats: PrivacyStats = Default::default();
    if stats.requests_blocked != 0 {
        return TestResult::Fail;
    }
    if stats.requests_allowed != 0 {
        return TestResult::Fail;
    }
    if stats.params_stripped != 0 {
        return TestResult::Fail;
    }
    if stats.fingerprint_blocked != 0 {
        return TestResult::Fail;
    }
    if stats.cookies_blocked != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_stats_total_requests() -> TestResult {
    let stats = PrivacyStats {
        requests_blocked: 10,
        requests_allowed: 90,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    if stats.total_requests() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_stats_block_rate_zero() -> TestResult {
    let stats = PrivacyStats {
        requests_blocked: 0,
        requests_allowed: 0,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    if stats.block_rate() != 0.0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_stats_block_rate_50_percent() -> TestResult {
    let stats = PrivacyStats {
        requests_blocked: 50,
        requests_allowed: 50,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    if (stats.block_rate() - 50.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_stats_block_rate_100_percent() -> TestResult {
    let stats = PrivacyStats {
        requests_blocked: 100,
        requests_allowed: 0,
        params_stripped: 0,
        fingerprint_blocked: 0,
        cookies_blocked: 0,
    };
    if (stats.block_rate() - 100.0).abs() >= 0.01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reset_stats() -> TestResult {
    reset_stats();
    increment_blocked();
    increment_blocked();
    let stats1 = get_stats();
    if stats1.requests_blocked == 0 {
        return TestResult::Fail;
    }
    reset_stats();
    let stats2 = get_stats();
    if stats2.requests_blocked != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_increment_params_stripped() -> TestResult {
    reset_stats();
    increment_params_stripped();
    increment_params_stripped();
    let stats = get_stats();
    if stats.params_stripped != 2 {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_increment_fingerprint_blocked() -> TestResult {
    reset_stats();
    increment_fingerprint_blocked();
    let stats = get_stats();
    if stats.fingerprint_blocked != 1 {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_increment_cookies_blocked() -> TestResult {
    reset_stats();
    increment_cookies_blocked();
    increment_cookies_blocked();
    increment_cookies_blocked();
    let stats = get_stats();
    if stats.cookies_blocked != 3 {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_is_tracker_exact_match() -> TestResult {
    if !is_tracker("google-analytics.com") {
        return TestResult::Fail;
    }
    if !is_tracker("doubleclick.net") {
        return TestResult::Fail;
    }
    if !is_tracker("facebook.net") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tracker_subdomain() -> TestResult {
    if !is_tracker("www.google-analytics.com") {
        return TestResult::Fail;
    }
    if !is_tracker("sub.doubleclick.net") {
        return TestResult::Fail;
    }
    if !is_tracker("cdn.facebook.net") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tracker_case_insensitive() -> TestResult {
    if !is_tracker("GOOGLE-ANALYTICS.COM") {
        return TestResult::Fail;
    }
    if !is_tracker("Google-Analytics.Com") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tracker_not_tracker() -> TestResult {
    if is_tracker("example.com") {
        return TestResult::Fail;
    }
    if is_tracker("google.com") {
        return TestResult::Fail;
    }
    if is_tracker("legitimate-site.org") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_tracker_partial_match_not_blocked() -> TestResult {
    if is_tracker("notgoogle-analytics.com") {
        return TestResult::Fail;
    }
    if is_tracker("google-analytics.com.example.org") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blocked_domains_not_empty() -> TestResult {
    if BLOCKED_DOMAINS.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blocked_domain_count() -> TestResult {
    if blocked_domain_count() <= 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_should_block_tracker_url() -> TestResult {
    reset_stats();
    let (blocked, domain) = should_block("https://google-analytics.com/collect");
    if !blocked {
        return TestResult::Fail;
    }
    if domain != Some(alloc::string::String::from("google-analytics.com")) {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_should_block_safe_url() -> TestResult {
    reset_stats();
    let (blocked, domain) = should_block("https://example.com/page");
    if blocked {
        return TestResult::Fail;
    }
    if domain != Some(alloc::string::String::from("example.com")) {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_should_block_subdomain_tracker() -> TestResult {
    reset_stats();
    let (blocked, _) = should_block("https://www.doubleclick.net/ad");
    if !blocked {
        return TestResult::Fail;
    }
    reset_stats();
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_utm() -> TestResult {
    let url = "https://example.com?utm_source=test&page=1";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com?page=1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_fbclid() -> TestResult {
    let url = "https://example.com?fbclid=abc123";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_gclid() -> TestResult {
    let url = "https://example.com?gclid=xyz&product=shoes";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com?product=shoes" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_multiple() -> TestResult {
    let url = "https://example.com?utm_source=a&utm_medium=b&id=123";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com?id=123" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_preserves_fragment() -> TestResult {
    let url = "https://example.com?utm_source=test#section";
    let cleaned = strip_tracking_params(url);
    if !cleaned.ends_with("#section") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_no_query() -> TestResult {
    let url = "https://example.com/page";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com/page" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_empty_after_strip() -> TestResult {
    let url = "https://example.com?utm_campaign=x";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_tracking_params_preserves_legit_params() -> TestResult {
    let url = "https://example.com?page=1&sort=asc&filter=new";
    let cleaned = strip_tracking_params(url);
    if cleaned != "https://example.com?page=1&sort=asc&filter=new" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clean_url_decodes_amp() -> TestResult {
    let url = "https://example.com?utm_source=test&amp;page=1";
    let cleaned = clean_url(url);
    if cleaned != "https://example.com?page=1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clean_url_removes_trailing_question_mark() -> TestResult {
    let url = "https://example.com?utm_source=only";
    let cleaned = clean_url(url);
    if cleaned.ends_with('?') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tracking_param_count_positive() -> TestResult {
    if tracking_param_count() <= 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strip_all_utm_variants() -> TestResult {
    let variants = [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "utm_cid",
        "utm_reader",
        "utm_name",
        "utm_social",
    ];
    for param in variants {
        let url = alloc::format!("https://example.com?{}=value&keep=this", param);
        let cleaned = strip_tracking_params(&url);
        if cleaned.contains(param) {
            return TestResult::Fail;
        }
        if !cleaned.contains("keep=this") {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_strip_social_trackers() -> TestResult {
    let trackers = ["fbclid", "gclid", "twclid", "igshid", "msclkid"];
    for param in trackers {
        let url = alloc::format!("https://example.com?{}=abc123", param);
        let cleaned = strip_tracking_params(&url);
        if cleaned.contains(param) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_strip_analytics_params() -> TestResult {
    let params = ["_ga", "_gl", "__hssc", "__hstc"];
    for param in params {
        let url = alloc::format!("https://example.com?{}=value&valid=true", param);
        let cleaned = strip_tracking_params(&url);
        if cleaned.contains(param) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_blocked_domains_contains_major_trackers() -> TestResult {
    let major_trackers =
        ["google-analytics.com", "doubleclick.net", "facebook.net", "hotjar.com", "mixpanel.com"];
    for tracker in major_trackers {
        if !BLOCKED_DOMAINS.contains(&tracker) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_url_with_only_tracking_params() -> TestResult {
    let url = "https://example.com?utm_source=email&utm_medium=cpc&fbclid=123";
    let cleaned = clean_url(url);
    if cleaned != "https://example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixed_case_tracking_params() -> TestResult {
    let url = "https://example.com?UTM_SOURCE=test&page=1";
    let cleaned = strip_tracking_params(url);
    if cleaned.to_lowercase().contains("utm_source") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
