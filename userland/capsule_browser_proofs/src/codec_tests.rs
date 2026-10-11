// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The saved-state record round-trips, writes its final sections, and reads
//! past sections this build does not keep.

use crate::browser::shell::store::codec::{encode, MAGIC, READER_DEFAULT, VERSION};
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::Persisted;

use super::codec_fixture::{full, record, MAX_STR};

#[test]
fn a_full_record_round_trips() {
    let p = decode(&encode(&full()));
    let marks: Vec<_> =
        p.bookmarks.iter().map(|b| (b.url.as_str(), b.title.as_str(), b.at_ms)).collect();
    assert_eq!(marks, [("https://a.com/x", "A \u{00e9}", -3), ("https://b.org/", "", 9)]);
}

#[test]
fn an_empty_record_round_trips_and_ends_in_the_default_sections() {
    let rec = encode(&Persisted::default());
    assert!(decode(&rec).bookmarks.is_empty());
    let mut want = MAGIC.to_vec();
    want.extend_from_slice(&[VERSION, 0, 0, 0, 0]);
    want.extend_from_slice(&READER_DEFAULT);
    assert_eq!(rec, want);
}

#[test]
fn a_record_with_groups_is_read_past_them() {
    let p = decode(&record(&[(b"https://a.com/", b"t")], &[(1, b"Work"), (2, b"Fun")]));
    assert_eq!(p.bookmarks.len(), 1);
    assert_eq!(p.bookmarks[0].at_ms, 7);
}

#[test]
fn long_strings_are_capped_on_a_char_boundary() {
    let mut p = full();
    p.bookmarks[0].title = "\u{00e9}".repeat(MAX_STR);
    let back = decode(&encode(&p));
    let t = &back.bookmarks[0].title;
    assert!(t.len() <= MAX_STR && t.len() >= MAX_STR - 1);
    assert!(t.chars().all(|c| c == '\u{00e9}'));
}
