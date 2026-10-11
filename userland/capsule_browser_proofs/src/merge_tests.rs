// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Merging this window's bookmarks with another window's save: a union by
//! URL where the newest copy wins, removals stay removed, within the cap.

use crate::browser::shell::bookmarks::MAX_BOOKMARKS;
use crate::browser::shell::store::merge::merge;
use crate::browser::shell::store::Persisted;
use crate::browser::shell::types::Bookmark;
use crate::browser::shell::Shell;

fn mark(url: &str, title: &str, at_ms: i64) -> Bookmark {
    Bookmark { url: url.into(), title: title.into(), at_ms }
}

fn state(bookmarks: Vec<Bookmark>) -> Persisted {
    Persisted { bookmarks }
}

fn urls(p: &Persisted) -> Vec<&str> {
    p.bookmarks.iter().map(|b| b.url.as_str()).collect()
}

#[test]
fn bookmarks_union_across_windows() {
    let p = merge(state(vec![mark("a", "", 1)]), state(vec![mark("b", "", 2)]), &[]);
    assert_eq!(urls(&p), ["a", "b"]);
}

#[test]
fn newest_copy_of_a_bookmark_wins() {
    let p = merge(state(vec![mark("a", "disk", 5)]), state(vec![mark("a", "mine", 3)]), &[]);
    assert_eq!(p.bookmarks.len(), 1);
    assert_eq!(p.bookmarks[0].title, "disk");
    let p = merge(state(vec![mark("a", "disk", 3)]), state(vec![mark("a", "mine", 5)]), &[]);
    assert_eq!(p.bookmarks[0].title, "mine");
}

#[test]
fn removed_bookmark_stays_removed() {
    let disk = state(vec![mark("a", "", 1), mark("b", "", 2)]);
    let p = merge(disk, state(vec![mark("b", "", 2)]), &["a".into()]);
    assert_eq!(urls(&p), ["b"]);
}

#[test]
fn bookmarks_bounded_dropping_oldest() {
    let disk = (0..MAX_BOOKMARKS as i64).map(|i| mark(&format!("d{i}"), "", i)).collect();
    let p = merge(state(disk), state(vec![mark("new", "", 10_000)]), &[]);
    assert_eq!(p.bookmarks.len(), MAX_BOOKMARKS);
    assert!(!urls(&p).contains(&"d0"));
    assert_eq!(urls(&p).last(), Some(&"new"));
}

#[test]
fn toggle_bookmark_records_and_clears_tombstone() {
    let mut shell = Shell::default();
    shell.toggle_bookmark("a", "", 1);
    assert!(shell.removed_bookmarks.is_empty());
    shell.toggle_bookmark("a", "", 2);
    assert_eq!(shell.removed_bookmarks, ["a"]);
    shell.toggle_bookmark("a", "", 3);
    assert!(shell.removed_bookmarks.is_empty());
    assert_eq!(shell.persisted().bookmarks[0].at_ms, 3);
}

#[test]
fn apply_takes_on_the_merged_bookmarks() {
    let mut shell = Shell::default();
    shell.toggle_bookmark("mine", "", 1);
    let merged = merge(state(vec![mark("other", "", 2)]), shell.persisted(), &[]);
    shell.apply(merged);
    let got: Vec<&str> = shell.bookmarks.iter().map(|b| b.url.as_str()).collect();
    assert_eq!(got, ["mine", "other"]);
}
