// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The window's in-memory visit log and its most visited sites.

use crate::browser::shell::types::Visit;
use crate::browser::shell::visits::{host_of, record, top_sites, MAX_VISITS};

fn site(host: &str, n: i64) -> Visit {
    let url = format!("https://{host}/p{n}");
    Visit { host: host_of(&url), url }
}

#[test]
fn record_drops_the_oldest_past_the_cap() {
    let mut v = Vec::new();
    for i in 0..MAX_VISITS + 10 {
        record(&mut v, &format!("https://a.com/{i}"));
    }
    assert_eq!(v.len(), MAX_VISITS);
    assert_eq!(v[0].url, "https://a.com/10");
    assert_eq!(v.last().map(|v| v.url.as_str()), Some("https://a.com/521"));
}

#[test]
fn an_immediate_duplicate_is_one_visit() {
    let mut v = Vec::new();
    record(&mut v, "https://a.com/");
    record(&mut v, "https://a.com/");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].host, "a.com");
}

#[test]
fn a_non_adjacent_repeat_is_a_new_visit() {
    let mut v = Vec::new();
    for u in ["https://a.com/", "https://b.com/", "https://a.com/"] {
        record(&mut v, u);
    }
    assert_eq!(v.len(), 3);
}

#[test]
fn top_sites_orders_by_count_then_recency() {
    let v =
        [site("a.com", 1), site("b.com", 2), site("a.com", 3), site("c.com", 4), site("b.com", 5)];
    let top = top_sites(&v, 5);
    let hosts: Vec<(&str, u32)> = top.iter().map(|(h, n)| (h.as_str(), *n)).collect();
    assert_eq!(hosts, [("b.com", 2), ("a.com", 2), ("c.com", 1)]);
    assert_eq!(top_sites(&v, 1).len(), 1);
    assert!(top_sites(&[], 3).is_empty());
}

#[test]
fn top_sites_skips_visits_without_a_host() {
    let mut v = Vec::new();
    record(&mut v, "about:blank");
    v.push(site("a.com", 2));
    assert_eq!(top_sites(&v, 5), [("a.com".into(), 1)]);
}

#[test]
fn host_of_parses_or_is_empty() {
    assert_eq!(host_of("https://example.com/a?b"), "example.com");
    assert_eq!(host_of("http://x.org:8080/"), "x.org");
    assert_eq!(host_of("not a url"), "");
    assert_eq!(host_of(""), "");
}
