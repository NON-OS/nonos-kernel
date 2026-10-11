// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! A page's title, read from its DOM: the first title, else the first h1.

use crate::browser::dom::parse;
use crate::browser::reader::title::title_of;

fn title(html: &str) -> Option<String> {
    title_of(&parse(html.as_bytes()))
}

#[test]
fn title_whitespace_is_collapsed_and_trimmed() {
    assert_eq!(title("<html><head><title> a  b </title></head></html>").as_deref(), Some("a b"));
    assert_eq!(title("<title>\n\tNews\n  today </title>").as_deref(), Some("News today"));
}

#[test]
fn without_a_title_the_first_h1_text_is_used() {
    assert_eq!(title("<body><h1>X<b>y</b></h1><h1>later</h1></body>").as_deref(), Some("Xy"));
}

#[test]
fn a_blank_title_falls_back_to_the_h1() {
    assert_eq!(title("<title>   </title><h1>Heading</h1>").as_deref(), Some("Heading"));
}

#[test]
fn script_and_style_inside_the_h1_are_not_title_text() {
    let html = "<h1>Real<script>var x = 1;</script><style>b{}</style> name</h1>";
    assert_eq!(title(html).as_deref(), Some("Real name"));
}

#[test]
fn no_title_and_no_h1_is_none() {
    assert_eq!(title("<p>just text</p>"), None);
    assert_eq!(title(""), None);
    assert_eq!(title("<title></title><h1>  </h1>"), None);
}

#[test]
fn a_long_title_is_capped_at_80_chars() {
    let long = "x".repeat(200);
    let t = title(&format!("<title>{long}</title>")).expect("title");
    assert_eq!(t.chars().count(), 80);
}

#[test]
fn the_cap_counts_chars_not_bytes() {
    let long = "\u{00e9}".repeat(200);
    let t = title(&format!("<title>{long}</title>")).expect("title");
    assert_eq!(t.chars().count(), 80);
    assert_eq!(t.len(), 160);
}

#[test]
fn title_entities_are_decoded() {
    assert_eq!(title("<title>Tom &amp; Jerry</title>").as_deref(), Some("Tom & Jerry"));
    assert_eq!(title("<title>a &lt;b&gt; c</title>").as_deref(), Some("a <b> c"));
    assert_eq!(title("<h1>Fish &amp; Chips</h1>").as_deref(), Some("Fish & Chips"));
}

#[test]
fn the_title_wins_over_the_h1() {
    assert_eq!(title("<title>T</title><h1>H</h1>").as_deref(), Some("T"));
}

/* The parser resolves references once; a title holding an escaped
 * reference keeps it as text rather than decoding it a second time. */
#[test]
fn a_title_is_not_decoded_twice() {
    assert_eq!(title("<title>a &amp;lt; b</title>").as_deref(), Some("a &lt; b"));
}
