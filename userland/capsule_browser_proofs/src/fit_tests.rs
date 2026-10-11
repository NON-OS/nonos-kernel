// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Text cut to a width with an ellipsis, char-boundary safe.

use crate::browser::ui::fit::truncate_to;

const ELLIPSIS: &str = "\u{2026}";

fn mono(s: &str) -> i32 {
    s.chars().count() as i32 * 8
}

#[test]
fn text_that_fits_is_unchanged() {
    assert_eq!(truncate_to("hello", 40, mono), "hello");
    assert_eq!(truncate_to("hello", 1000, mono), "hello");
    assert_eq!(truncate_to("", 0, mono), "");
}

#[test]
fn a_cut_ends_in_an_ellipsis_and_fits() {
    for max_w in 8..=120 {
        let out = truncate_to("the quick brown fox", max_w, mono);
        assert!(mono(&out) <= max_w, "{max_w}: {out:?}");
        assert!(out.ends_with(ELLIPSIS), "{max_w}: {out:?}");
    }
}

#[test]
fn the_cut_keeps_the_longest_prefix_that_fits() {
    assert_eq!(truncate_to("abcdefgh", 40, mono), "abcd\u{2026}");
    assert_eq!(truncate_to("abcdefgh", 47, mono), "abcd\u{2026}");
    assert_eq!(truncate_to("abcdefgh", 63, mono), "abcdef\u{2026}");
    assert_eq!(truncate_to("abcdefgh", 64, mono), "abcdefgh");
}

#[test]
fn multibyte_text_is_cut_on_char_boundaries() {
    let s = "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{6587}\u{7ae0}\u{1f600}\u{00e9}";
    for max_w in 0..=80 {
        let out = truncate_to(s, max_w, mono);
        assert!(mono(&out) <= max_w || out.is_empty(), "{max_w}");
        let body = out.trim_end_matches(ELLIPSIS);
        assert!(s.starts_with(body), "{max_w}: {out:?}");
    }
}

#[test]
fn a_width_below_the_ellipsis_gives_nothing() {
    assert_eq!(truncate_to("abcdef", 7, mono), "");
    assert_eq!(truncate_to("abcdef", 0, mono), "");
    assert_eq!(truncate_to("abcdef", -5, mono), "");
}

#[test]
fn exactly_the_ellipsis_width_gives_only_the_ellipsis() {
    assert_eq!(truncate_to("abcdef", 8, mono), ELLIPSIS);
    assert_eq!(truncate_to("abcdef", 15, mono), ELLIPSIS);
}

#[test]
fn a_proportional_measure_is_respected() {
    let wide = |s: &str| s.chars().map(|c| if c == 'W' { 20 } else { 5 }).sum::<i32>();
    let out = truncate_to("WWWWiiii", 50, wide);
    assert!(wide(&out) <= 50);
    assert_eq!(out, "WW\u{2026}");
}
