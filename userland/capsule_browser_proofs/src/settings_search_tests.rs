// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The search template the settings page takes: an http or https address
//! with %s, trimmed, and the default when there is no custom one.

use crate::browser::shell::search::{check, template, DEFAULT_SEARCH};

#[test]
fn a_template_with_an_address_and_the_words_slot_is_taken_trimmed() {
    assert_eq!(check("  https://s.example/?q=%s "), Ok("https://s.example/?q=%s".into()));
    assert_eq!(check("HTTP://x.org/find/%s"), Ok("HTTP://x.org/find/%s".into()));
    assert_eq!(check(DEFAULT_SEARCH), Ok(DEFAULT_SEARCH.into()));
}

#[test]
fn a_template_is_refused_with_its_reason() {
    assert_eq!(check("https://s.example/?q="), Err("Put %s where the search words go."));
    assert_eq!(check("s.example/?q=%s"), Err("A template starts with https:// or http://."));
    assert_eq!(check("ftp://s.example/%s"), Err("A template starts with https:// or http://."));
    assert_eq!(check("https://"), Err("A template starts with https:// or http://."));
    assert_eq!(check(""), Err("A template starts with https:// or http://."));
    assert_eq!(check("https://a b/?q=%s"), Err("A template has no spaces."));
    let long = format!("https://a.org/?q=%s&p={}", "x".repeat(600));
    assert_eq!(check(&long), Err("That template is too long."));
}

#[test]
fn no_custom_template_searches_the_default() {
    assert_eq!(template(None), DEFAULT_SEARCH);
    assert_eq!(template(Some("https://x.org/%s")), "https://x.org/%s");
    assert!(DEFAULT_SEARCH.starts_with("https://html.duckduckgo.com/"));
}
