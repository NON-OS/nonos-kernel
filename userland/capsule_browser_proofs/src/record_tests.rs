// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Every saved record is one size, so the disk store can overwrite it in
//! place, and the padding reads back as nothing.

use alloc::format;

use crate::browser::shell::store::codec::encode;
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::record::{fixed, RECORD_BYTES};
use crate::browser::shell::store::Persisted;
use crate::browser::shell::types::Bookmark;

use super::codec_fixture::full;

fn mark(i: usize, len: usize) -> Bookmark {
    Bookmark {
        url: format!("https://{i}.example/{}", "x".repeat(len)),
        title: format!("t{i}"),
        at_ms: i as i64,
    }
}

#[test]
fn an_empty_and_a_full_window_write_the_same_length() {
    assert_eq!(fixed(&mut Persisted::default()).len(), RECORD_BYTES);
    assert_eq!(fixed(&mut full()).len(), RECORD_BYTES);
}

#[test]
fn the_padded_record_reads_back_as_the_unpadded_one() {
    let mut p = full();
    let rec = fixed(&mut p);
    assert_eq!(encode(&decode(&rec)), encode(&p));
}

#[test]
fn a_window_too_big_for_the_record_drops_its_oldest_bookmarks() {
    let mut p =
        Persisted { bookmarks: (0..200).map(|i| mark(i, 400)).collect(), ..Persisted::default() };
    let rec = fixed(&mut p);
    assert_eq!(rec.len(), RECORD_BYTES);
    assert!(p.bookmarks.len() < 200 && !p.bookmarks.is_empty());
    assert_eq!(p.bookmarks.last().map(|b| b.at_ms), Some(199));
    let back = decode(&rec);
    assert_eq!(back.bookmarks.len(), p.bookmarks.len());
    assert_eq!(back.bookmarks[0].at_ms, p.bookmarks[0].at_ms);
}
