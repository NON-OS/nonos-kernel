// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! What the reader keeps of a page: the headings, paragraphs and quotes of
//! its article or main, without its navigation, chrome or scripts.

use crate::browser::dom::parse;
use crate::browser::reader::extract::{extract, Article, Para};

fn read(html: &str) -> Article {
    extract(&parse(html.as_bytes()), "")
}

fn texts(a: &Article) -> Vec<&str> {
    a.paras.iter().map(|p| p.text()).collect()
}

#[test]
fn nav_header_footer_and_scripts_are_excluded() {
    let a = read(
        "<body><nav><p>Home About Contact</p></nav><header><p>Site banner text</p></header>\
         <p>The real story begins.</p><script>var no = 'leak here';</script>\
         <aside><p>Related links list</p></aside><footer><p>Copyright notice here</p></footer></body>",
    );
    assert_eq!(texts(&a), ["The real story begins."]);
}

#[test]
fn an_article_is_preferred_over_the_body() {
    let a = read(
        "<body><p>Outside the article.</p><article><h2>Inner heading</h2>\
         <p>Inside the article.</p></article><p>Also outside here.</p></body>",
    );
    assert_eq!(texts(&a), ["Inner heading", "Inside the article."]);
    assert!(matches!(a.paras[0], Para::Heading(_)));
}

#[test]
fn main_counts_as_the_article_root() {
    let a = read("<div><p>Chrome text here</p></div><main><p>Main body text.</p></main>");
    assert_eq!(texts(&a), ["Main body text."]);
}

#[test]
fn a_blockquote_becomes_a_quote() {
    let a = read("<p>He said this:</p><blockquote>To be or not to be.</blockquote>");
    assert!(matches!(&a.paras[1], Para::Quote(q) if q == "To be or not to be."));
}

#[test]
fn list_items_are_text_and_inline_markup_is_flattened() {
    let a = read("<ul><li>first <b>bold</b> item</li><li>second   spaced\n item</li></ul>");
    assert_eq!(texts(&a), ["first bold item", "second spaced item"]);
    assert!(a.paras.iter().all(|p| matches!(p, Para::Text(_))));
}

#[test]
fn single_word_blocks_are_dropped() {
    let a = read("<p>Share</p><p>Two words</p><h2>Menu</h2>");
    assert_eq!(texts(&a), ["Two words"]);
}

#[test]
fn words_are_counted_over_the_kept_blocks() {
    let a =
        read("<h2>A heading here</h2><p>one two three four</p><blockquote>five six</blockquote>");
    assert_eq!(a.words, 3 + 4 + 2);
}
