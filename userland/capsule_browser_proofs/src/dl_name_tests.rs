// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The names downloads are saved under, and sizes as people read them.

use crate::browser::shell::dl_name::{name_of, unique_name};
use crate::browser::shell::downloads::human_bytes;

#[test]
fn human_bytes_boundaries() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(1023), "1023 B");
    assert_eq!(human_bytes(1024), "1 KB");
    assert_eq!(human_bytes(1024 * 1024 - 1), "1023 KB");
    assert_eq!(human_bytes(1024 * 1024), "1.0 MB");
    assert_eq!(human_bytes(3 * 1024 * 1024 / 2), "1.5 MB");
    assert_eq!(human_bytes((1 << 30) - 1), "1023.9 MB");
    assert_eq!(human_bytes(1 << 30), "1.0 GB");
    assert_eq!(human_bytes(5 * (1 << 30) / 4), "1.2 GB");
    assert!(human_bytes(u64::MAX).ends_with(" GB"));
}

#[test]
fn unique_name_appends_a_counter_before_the_extension() {
    let ex: Vec<String> = ["a.pdf", "a (2).pdf", "b", ".x"].iter().map(|s| (*s).into()).collect();
    assert_eq!(unique_name(&ex, "new.pdf"), "new.pdf");
    assert_eq!(unique_name(&ex, "a.pdf"), "a (3).pdf");
    assert_eq!(unique_name(&ex, "b"), "b (2)");
    assert_eq!(unique_name(&ex, ".x"), ".x (2)");
    assert_eq!(unique_name(&["t.tar.gz".into()], "t.tar.gz"), "t.tar (2).gz");
    assert_eq!(unique_name(&[], "z"), "z");
}

#[test]
fn name_of_sanitises_the_last_segment() {
    assert_eq!(name_of("https://x.com/a/b.pdf?x=1#y"), "b.pdf");
    assert_eq!(name_of("https://x.com/a\u{1}b\u{7f}.zip"), "a_b_.zip");
    assert_eq!(name_of("https://x.com"), "download");
    assert_eq!(name_of("https://x.com/"), "download");
    assert_eq!(name_of("https://x.com/a/.."), "download");
    assert_eq!(name_of("https://x.com/a/."), "download");
    assert_eq!(name_of(""), "download");
}
