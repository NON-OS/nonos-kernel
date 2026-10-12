// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Breaking text into lines no wider than a column, at whitespace.

use crate::browser::ui::wrap::wrap;

fn mono(s: &str) -> i32 {
    s.chars().count() as i32 * 8
}

fn lines(text: &str, max_w: i32) -> Vec<&str> {
    wrap(text, max_w, mono).into_iter().map(|(s, e)| &text[s..e]).collect()
}

#[test]
fn empty_and_blank_text_gives_no_lines() {
    assert!(wrap("", 100, mono).is_empty());
    assert!(wrap("   \n\t ", 100, mono).is_empty());
}

#[test]
fn short_text_is_one_line() {
    assert_eq!(lines("hello world", 200), ["hello world"]);
}

#[test]
fn lines_break_at_spaces_and_stay_within_width() {
    let text = "the quick brown fox jumps over the lazy dog";
    for max_w in (40..400).step_by(8) {
        let out = lines(text, max_w);
        for l in &out {
            assert!(mono(l) <= max_w, "{max_w}: {l:?}");
            assert!(!l.starts_with(' ') && !l.ends_with(' '));
        }
        assert_eq!(out.join(" "), text, "{max_w}");
    }
}

#[test]
fn a_line_is_filled_greedily() {
    assert_eq!(lines("aa bb cc dd", 40), ["aa bb", "cc dd"]);
    assert_eq!(lines("aa bb cc dd", 39), ["aa", "bb", "cc", "dd"]);
}

#[test]
fn an_overlong_word_takes_a_line_of_its_own() {
    assert_eq!(lines("a supercalifragilistic b", 40), ["a", "supercalifragilistic", "b"]);
    assert_eq!(lines("word", 0), ["word"]);
}

#[test]
fn every_word_survives_in_order() {
    let text = "  one\ttwo\n\nthree   four  ";
    let words: Vec<&str> = lines(text, 48).iter().flat_map(|l| l.split_whitespace()).collect();
    assert_eq!(words, ["one", "two", "three", "four"]);
}

#[test]
fn multibyte_text_breaks_on_char_boundaries() {
    let text = "\u{65e5}\u{672c} \u{8a9e}\u{306e} \u{1f600}\u{1f600}\u{1f600} \u{00e9}t\u{00e9}";
    for max_w in 0..120 {
        for (s, e) in wrap(text, max_w, mono) {
            assert!(text.is_char_boundary(s) && text.is_char_boundary(e));
            assert!(s < e);
        }
    }
}

#[test]
fn ranges_are_increasing_and_disjoint() {
    let text = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do";
    let r = wrap(text, 80, mono);
    assert!(r.windows(2).all(|p| p[0].1 < p[1].0));
}
