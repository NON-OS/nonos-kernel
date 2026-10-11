// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! A short, foreign, newer or damaged saved-state record decodes to the
//! defaults, or drops only the bad entry, and never panics.

use crate::browser::shell::bookmarks::MAX_BOOKMARKS;
use crate::browser::shell::store::codec::{encode, VERSION};
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::Persisted;

use super::codec_fixture::{full, mark, record};

#[test]
fn empty_foreign_or_newer_bytes_decode_to_default() {
    assert!(decode(&[]).bookmarks.is_empty());
    let mut bad = encode(&full());
    bad[0] = b'X';
    assert!(decode(&bad).bookmarks.is_empty());
    for v in [0, VERSION + 1, 255] {
        let mut b = encode(&full());
        b[4] = v;
        assert!(decode(&b).bookmarks.is_empty(), "version {v}");
    }
}

#[test]
fn every_truncation_decodes_to_default_without_panic() {
    let rec = record(&[(b"https://a.com/", b"t")], &[(3, b"g")]);
    for n in 0..rec.len() {
        assert!(decode(&rec[..n]).bookmarks.is_empty(), "cut at {n}");
    }
    assert_eq!(decode(&rec).bookmarks.len(), 1);
    let rec = encode(&full());
    for n in 0..rec.len() {
        assert!(decode(&rec[..n]).bookmarks.is_empty(), "cut at {n}");
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let rec = encode(&full());
    for i in 0..rec.len() {
        for v in [0u8, 1, 0x7f, 0x80, 0xff] {
            let mut b = rec.clone();
            b[i] = v;
            let _ = decode(&b);
        }
    }
}

#[test]
fn over_cap_counts_are_truncated() {
    let urls: Vec<String> = (0..300).map(|i| format!("https://a.com/{i}")).collect();
    let marks: Vec<(&[u8], &[u8])> = urls.iter().map(|u| (u.as_bytes(), &b"t"[..])).collect();
    assert_eq!(decode(&record(&marks, &[])).bookmarks.len(), MAX_BOOKMARKS);
    let big = Persisted { bookmarks: urls.iter().map(|u| mark(u, "", 0)).collect() };
    assert_eq!(decode(&encode(&big)).bookmarks.len(), MAX_BOOKMARKS);
}

#[test]
fn a_non_utf8_string_drops_only_that_entry() {
    let rec = record(
        &[(b"https://a.com/", b"ok"), (b"\xff\xfe", b"t"), (b"https://c.com/", b"\xc3")],
        &[(1, b"\x80bad"), (2, b"good")],
    );
    let p = decode(&rec);
    assert_eq!(p.bookmarks.len(), 1);
    assert_eq!(p.bookmarks[0].url, "https://a.com/");
}
