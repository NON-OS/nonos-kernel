// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The browser's appearance is kept as a byte appended to the saved-state
//! record: Dark by default, Dark for a record written before the byte
//! existed, and the palette in force follows it.

use crate::browser::shell::kept::Appearance;
use crate::browser::shell::store::codec::encode;
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::merge::{merge, Removed};
use crate::browser::shell::store::Persisted;
use crate::browser::shell::Shell;
use crate::browser::tokens::{is_dark, palette, set_dark, DARK, LIGHT};

use super::codec_fixture::{full, record};

#[test]
fn light_and_dark_round_trip() {
    for a in [Appearance::Light, Appearance::Dark] {
        let p = Persisted { appearance: a, ..full() };
        assert_eq!(decode(&encode(&p)).appearance, a);
    }
}

#[test]
fn a_record_without_the_section_reads_whole_and_dark() {
    let p = decode(&record(&[(b"https://a.com/", b"t")], &[(1, b"Work")]));
    assert_eq!((p.bookmarks.len(), p.groups.len()), (1, 1));
    assert_eq!(p.appearance, Appearance::Dark);
    let mut light = encode(&Persisted { appearance: Appearance::Light, ..full() });
    light.pop();
    let p = decode(&light);
    assert_eq!((p.bookmarks.len(), p.appearance), (2, Appearance::Dark));
}

#[test]
fn a_short_corrupt_or_unknown_record_reads_dark() {
    assert_eq!(Persisted::default().appearance, Appearance::Dark);
    assert_eq!(decode(&[]).appearance, Appearance::Dark);
    assert_eq!(decode(b"XBR1\x01").appearance, Appearance::Dark);
    let mut odd = encode(&Persisted { appearance: Appearance::Light, ..full() });
    let n = odd.len();
    odd[n - 1] = 7;
    assert_eq!(decode(&odd).appearance, Appearance::Dark);
}

#[test]
fn the_window_keeps_and_merges_its_own_appearance() {
    assert_eq!(Shell::default().appearance, Appearance::Dark);
    let mut s = Shell::default();
    s.apply(Persisted { appearance: Appearance::Light, ..Default::default() });
    assert_eq!(s.persisted().appearance, Appearance::Light);
    let disk = Persisted { appearance: Appearance::Dark, ..Default::default() };
    let none = Removed { bookmarks: &[], groups: &[] };
    assert_eq!(merge(disk, s.persisted(), none).appearance, Appearance::Light);
    assert_eq!(Appearance::Light.toggled(), Appearance::Dark);
}

#[test]
fn the_palette_starts_dark_and_follows_the_choice() {
    assert!(is_dark() && core::ptr::eq(palette(), &DARK));
    set_dark(false);
    assert!(!is_dark() && core::ptr::eq(palette(), &LIGHT));
    set_dark(true);
    assert!(core::ptr::eq(palette(), &DARK));
}
