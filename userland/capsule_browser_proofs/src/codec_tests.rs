// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The saved-state record round-trips its bookmarks, tab groups and reader
//! settings, and writes the default sections for an empty window.

use crate::browser::shell::groups::MAX_GROUPS;
use crate::browser::shell::kept::ReaderPrefs;
use crate::browser::shell::store::codec::{encode, MAGIC, VERSION};
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::Persisted;

use super::codec_fixture::{full, record, MAX_STR};

#[test]
fn a_full_record_round_trips() {
    let p = decode(&encode(&full()));
    let marks: Vec<_> =
        p.bookmarks.iter().map(|b| (b.url.as_str(), b.title.as_str(), b.at_ms)).collect();
    assert_eq!(marks, [("https://a.com/x", "A \u{00e9}", -3), ("https://b.org/", "", 9)]);
    let groups: Vec<_> = p.groups.iter().map(|g| (g.id, g.name.as_str(), g.color)).collect();
    assert_eq!(groups, [(4, "Work", 3)]);
    assert_eq!(p.reader, ReaderPrefs { theme: 2, size: 4, width: 0, show_time: false });
}

#[test]
fn an_empty_record_round_trips_and_ends_in_the_default_sections() {
    let rec = encode(&Persisted::default());
    let p = decode(&rec);
    assert!(p.bookmarks.is_empty() && p.groups.is_empty());
    assert_eq!(p.reader, ReaderPrefs::default());
    let mut want = MAGIC.to_vec();
    want.extend_from_slice(&[VERSION, 0, 0, 0, 0, 0, 1, 1, 1, 1]);
    assert_eq!(rec, want);
}

#[test]
fn a_record_with_groups_reads_them_and_its_reader_bytes() {
    let p = decode(&record(&[(b"https://a.com/", b"t")], &[(1, b"Work"), (2, b"Fun")]));
    assert_eq!(p.bookmarks.len(), 1);
    assert_eq!(p.bookmarks[0].at_ms, 7);
    let names: Vec<_> = p.groups.iter().map(|g| (g.id, g.name.as_str(), g.color)).collect();
    assert_eq!(names, [(1, "Work", 1), (2, "Fun", 1)]);
    assert_eq!(p.reader, ReaderPrefs { theme: 1, size: 2, width: 1, show_time: true });
}

#[test]
fn groups_past_the_cap_are_skipped_and_reader_bytes_kept_raw() {
    let names: Vec<String> = (0..12).map(|i| format!("g{i}")).collect();
    let groups: Vec<(u8, &[u8])> =
        names.iter().enumerate().map(|(i, n)| (i as u8, n.as_bytes())).collect();
    let mut rec = record(&[], &groups);
    let n = rec.len();
    rec[n - 4..].copy_from_slice(&[9, 9, 9, 0]);
    let p = decode(&rec);
    assert_eq!(p.groups.len(), MAX_GROUPS);
    assert_eq!((p.reader.theme, p.reader.size, p.reader.show_time), (9, 9, false));
    assert_eq!(p.reader.clamped(), ReaderPrefs { theme: 2, size: 4, width: 2, show_time: false });
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
