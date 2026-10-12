// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The reader's article as a whole: its title, the site its address names,
//! an empty page, the paragraph cap, and the reading time.

use crate::browser::dom::parse;
use crate::browser::reader::extract::{extract, minutes, Article, MAX_PARAS};
use crate::grid_page::card_page;

fn read(html: &str) -> Article {
    extract(&parse(html.as_bytes()), "")
}

fn texts(a: &Article) -> Vec<&str> {
    a.paras.iter().map(|p| p.text()).collect()
}

#[test]
fn title_and_site_come_from_the_document() {
    let mut dom = parse(b"<title>My  Story</title><p>Some body text.</p>");
    dom.base = "https://news.example.org/a/b".into();
    let a = extract(&dom, "");
    assert_eq!((a.title.as_str(), a.site.as_str()), ("My Story", "news.example.org"));
}

#[test]
fn the_site_comes_from_the_address_over_a_stale_base() {
    let mut dom = parse(b"<p>Some body text.</p>");
    dom.base = "https://example.com/".into();
    assert_eq!(extract(&dom, "https://www.rust-lang.org/learn").site, "www.rust-lang.org");
    assert_eq!(extract(&dom, "about:nonos").site, "about:nonos");
}

#[test]
fn an_empty_document_gives_an_empty_article() {
    for html in ["", "<html></html>", "<body><nav><p>only nav here</p></nav></body>"] {
        let a = read(html);
        assert!(a.paras.is_empty() && a.words == 0 && a.title.is_empty() && a.site.is_empty());
    }
    let a = extract(&parse(&[0xff, 0xfe, 0x00]), "");
    assert!(a.paras.is_empty());
}

#[test]
fn paragraphs_are_capped() {
    let html: String = (0..MAX_PARAS + 50).map(|i| format!("<p>para number {i}</p>")).collect();
    let a = read(&html);
    assert_eq!(a.paras.len(), MAX_PARAS);
    assert_eq!(a.paras[0].text(), "para number 0");
}

#[test]
fn the_grid_fixture_reads_as_three_paragraphs() {
    let a = read(&card_page("1fr 1fr 1fr"));
    assert_eq!(a.paras.len(), 3);
    assert_eq!(a.words, 15);
    assert!(texts(&a).iter().all(|t| !t.contains('{')));
}

#[test]
fn minutes_is_at_least_one_at_220_wpm() {
    assert_eq!(minutes(0), 1);
    assert_eq!(minutes(219), 1);
    assert_eq!(minutes(440), 2);
    assert_eq!(minutes(659), 2);
    assert_eq!(minutes(660), 3);
    assert_eq!(minutes(u32::MAX), u32::MAX / 220);
}
