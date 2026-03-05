// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Tracker domain blocking.

extern crate alloc;

use alloc::string::String;

use super::stats;

pub const BLOCKED_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "googleadservices.com",
    "doubleclick.net",
    "facebook.com",
    "connect.facebook.net",
    "facebook.net",
    "fbcdn.net",
    "amazon-adsystem.com",
    "scorecardresearch.com",
    "quantserve.com",
    "adsrvr.org",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    "chartbeat.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "hotjar.com",
    "fullstory.com",
    "clarity.ms",
    "newrelic.com",
    "nr-data.net",
    "bugsnag.com",
    "sentry.io",
    "mouseflow.com",
    "crazyegg.com",
    "optimizely.com",
    "branch.io",
    "adjust.com",
    "appsflyer.com",
    "mparticle.com",
    "onesignal.com",
    "pushwoosh.com",
    "urbanairship.com",
    "leanplum.com",
    "braze.com",
    "intercom.io",
    "drift.com",
    "zendesk.com",
    "hubspot.com",
    "hs-analytics.net",
    "hs-scripts.com",
    "pardot.com",
    "marketo.com",
    "eloqua.com",
    "omtrdc.net",
    "demdex.net",
    "adnxs.com",
    "rlcdn.com",
    "bluekai.com",
    "krxd.net",
    "exelator.com",
    "agkn.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "indexww.com",
    "33across.com",
    "sharethrough.com",
    "media.net",
    "yieldmo.com",
    "undertone.com",
    "conversantmedia.com",
    "sonobi.com",
    "bidswitch.net",
    "bidtellect.com",
    "zemanta.com",
    "nativo.com",
    "revcontent.com",
    "zergnet.com",
    "content-ad.net",
    "dianomi.com",
    "yahoo.com/analytics",
    "ads-twitter.com",
    "ads.linkedin.com",
    "snap.com/analytics",
    "tiktok.com/analytics",
    "pinterest.com/analytics",
    "reddit.com/pixel",
];

pub fn is_tracker(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();

    for blocked in BLOCKED_DOMAINS {
        if domain_lower == *blocked {
            return true;
        }
        if domain_lower.ends_with(&format!(".{}", blocked)) {
            return true;
        }
    }

    false
}

pub fn should_block(url: &str) -> (bool, Option<String>) {
    let domain = extract_domain(url);

    if let Some(ref d) = domain {
        if is_tracker(d) {
            stats::increment_blocked();
            return (true, domain);
        }
    }

    stats::increment_allowed();
    (false, domain)
}

fn extract_domain(url: &str) -> Option<String> {
    let url = url.trim();

    let after_scheme = if url.starts_with("https://") {
        &url[8..]
    } else if url.starts_with("http://") {
        &url[7..]
    } else {
        url
    };

    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let host_port = &after_scheme[..host_end];

    let host = if let Some(port_start) = host_port.rfind(':') {
        if host_port[port_start + 1..].chars().all(|c| c.is_ascii_digit()) {
            &host_port[..port_start]
        } else {
            host_port
        }
    } else {
        host_port
    };

    if host.is_empty() {
        None
    } else {
        Some(String::from(host))
    }
}

pub fn blocked_domain_count() -> usize {
    BLOCKED_DOMAINS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tracker() {
        assert!(is_tracker("google-analytics.com"));
        assert!(is_tracker("www.google-analytics.com"));
        assert!(is_tracker("sub.google-analytics.com"));
        assert!(!is_tracker("example.com"));
        assert!(!is_tracker("google.com"));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), Some(String::from("example.com")));
        assert_eq!(extract_domain("http://example.com:8080/path"), Some(String::from("example.com")));
        assert_eq!(extract_domain("example.com"), Some(String::from("example.com")));
    }
}
