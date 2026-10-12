// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The custom search template is kept in a section appended to the
//! saved-state record: it round-trips, and a record from before it, or one
//! holding a template this build refuses, searches the default engine.

use crate::browser::shell::kept::Appearance;
use crate::browser::shell::store::codec::encode;
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::merge::{merge, Removed};
use crate::browser::shell::store::Persisted;
use crate::browser::shell::Shell;

use super::codec_fixture::{full, record};

const MINE: &str = "https://find.example/?q=%s";

#[test]
fn a_custom_template_round_trips_after_the_appearance() {
    let p = Persisted { search: Some(MINE.into()), ..full() };
    let back = decode(&encode(&p));
    assert_eq!(back.search.as_deref(), Some(MINE));
    assert_eq!((back.appearance, back.bookmarks.len()), (Appearance::Light, 2));
    assert_eq!(decode(&encode(&full())).search, None);
}

#[test]
fn a_record_from_before_the_search_section_reads_the_default() {
    let mut rec = record(&[(b"https://a.com/", b"t")], &[(1, b"Work")]);
    assert_eq!(decode(&rec).search, None);
    rec.push(0);
    let p = decode(&rec);
    assert_eq!((p.search, p.appearance, p.bookmarks.len()), (None, Appearance::Light, 1));
}

#[test]
fn a_cut_or_refused_template_reads_the_default() {
    let good = encode(&Persisted { search: Some(MINE.into()), ..full() });
    for cut in 1..=MINE.len() + 2 {
        let p = decode(&good[..good.len() - cut]);
        assert_eq!(p.search, None, "cut {cut}");
        assert_eq!(p.bookmarks.len(), 2);
    }
    let bad = encode(&Persisted { search: Some("https://no.slot/".into()), ..full() });
    assert_eq!(decode(&bad).search, None);
}

#[test]
fn the_window_keeps_and_merges_its_own_template() {
    let mut s = Shell::default();
    s.apply(Persisted { search: Some(MINE.into()), ..Default::default() });
    assert_eq!(s.persisted().search.as_deref(), Some(MINE));
    let disk = Persisted { search: Some("https://other.example/%s".into()), ..Default::default() };
    let none = Removed { bookmarks: &[], groups: &[] };
    assert_eq!(merge(disk, s.persisted(), none).search.as_deref(), Some(MINE));
}
