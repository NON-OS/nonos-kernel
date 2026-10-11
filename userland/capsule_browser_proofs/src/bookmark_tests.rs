// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Bookmarks: the star adds a page once and takes it out again, within a cap.

use crate::browser::shell::bookmarks::{contains, toggle, MAX_BOOKMARKS};
use crate::browser::shell::types::Bookmark;

#[test]
fn bookmark_toggle_adds_then_removes() {
    let mut b: Vec<Bookmark> = Vec::new();
    assert!(toggle(&mut b, "https://a.com/", "A"));
    assert!(contains(&b, "https://a.com/"));
    assert_eq!((b[0].url.as_str(), b[0].title.as_str()), ("https://a.com/", "A"));
    assert!(!toggle(&mut b, "https://a.com/", "A"));
    assert!(b.is_empty() && !contains(&b, "https://a.com/"));
}

#[test]
fn toggling_twice_is_the_identity() {
    let mut b: Vec<Bookmark> = Vec::new();
    toggle(&mut b, "https://keep.com/", "");
    for _ in 0..3 {
        toggle(&mut b, "https://x.com/", "");
        toggle(&mut b, "https://x.com/", "");
    }
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].url, "https://keep.com/");
}

#[test]
fn an_empty_url_is_never_bookmarked() {
    let mut b: Vec<Bookmark> = Vec::new();
    assert!(!toggle(&mut b, "", "t"));
    assert!(b.is_empty());
}

#[test]
fn a_full_list_refuses_new_but_still_removes() {
    let mut b: Vec<Bookmark> = Vec::new();
    for i in 0..MAX_BOOKMARKS {
        assert!(toggle(&mut b, &format!("https://a.com/{i}"), ""));
    }
    assert!(!toggle(&mut b, "https://new.com/", ""));
    assert_eq!(b.len(), MAX_BOOKMARKS);
    assert!(!toggle(&mut b, "https://a.com/0", ""));
    assert_eq!(b.len(), MAX_BOOKMARKS - 1);
    assert!(toggle(&mut b, "https://new.com/", ""));
}
