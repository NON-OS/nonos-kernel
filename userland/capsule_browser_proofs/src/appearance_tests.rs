// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The browser's appearance is kept as a byte appended to the saved-state
//! record: System by default, System for a record written before the byte
//! existed, and the palette in force follows it.

use crate::browser::shell::kept::Appearance;
use crate::browser::shell::store::codec::encode;
use crate::browser::shell::store::decode::decode;
use crate::browser::shell::store::merge::{merge, Removed};
use crate::browser::shell::store::Persisted;
use crate::browser::shell::Shell;
use crate::browser::tokens::system::from_roles;
use crate::browser::tokens::{key, mode, palette, set_mode, DARK, LIGHT};
use nonos_toolkit::theme::{roles, snapshot};

use super::codec_fixture::{full, record};

#[test]
fn every_appearance_round_trips() {
    for a in [Appearance::Light, Appearance::Dark, Appearance::System] {
        let p = Persisted { appearance: a, ..full() };
        assert_eq!(decode(&encode(&p)).appearance, a);
    }
}

#[test]
fn a_record_without_the_section_reads_whole_and_system() {
    let p = decode(&record(&[(b"https://a.com/", b"t")], &[(1, b"Work")]));
    assert_eq!((p.bookmarks.len(), p.groups.len()), (1, 1));
    assert_eq!(p.appearance, Appearance::System);
    let mut light = encode(&Persisted { appearance: Appearance::Light, ..full() });
    light.truncate(light.len() - 4);
    let p = decode(&light);
    assert_eq!((p.bookmarks.len(), p.appearance), (2, Appearance::System));
}

#[test]
fn a_short_corrupt_or_unknown_record_reads_system() {
    assert_eq!(Persisted::default().appearance, Appearance::System);
    assert_eq!(decode(&[]).appearance, Appearance::System);
    assert_eq!(decode(b"XBR1\x01").appearance, Appearance::System);
    let mut odd = encode(&Persisted { appearance: Appearance::Light, ..full() });
    let n = odd.len();
    odd[n - 4] = 7;
    assert_eq!(decode(&odd).appearance, Appearance::System);
}

#[test]
fn the_window_keeps_and_merges_its_own_appearance() {
    assert_eq!(Shell::default().appearance, Appearance::System);
    let mut s = Shell::default();
    s.apply(Persisted { appearance: Appearance::Light, ..Default::default() });
    assert_eq!(s.persisted().appearance, Appearance::Light);
    let disk = Persisted { appearance: Appearance::Dark, ..Default::default() };
    let none = Removed { bookmarks: &[], groups: &[] };
    assert_eq!(merge(disk, s.persisted(), none).appearance, Appearance::Light);
    assert_eq!(
        [0, 1, 2].map(Appearance::from_byte),
        [Appearance::Light, Appearance::Dark, Appearance::System]
    );
}

/* The key moves with the appearance, and under System carries the OS
 * theme's revision; the palette follows the mode in force. */
#[test]
fn the_palette_starts_on_system_and_follows_the_choice() {
    assert_eq!(mode(), Appearance::System);
    assert_eq!(key(), 2 << 32 | snapshot().revision as u64);
    assert_eq!(palette().ground, from_roles(&roles()).ground);
    set_mode(Appearance::Light);
    assert_eq!((key(), palette().ground, palette().ink), (0, LIGHT.ground, LIGHT.ink));
    set_mode(Appearance::Dark);
    assert_eq!((key(), palette().ground, palette().ink), (1 << 32, DARK.ground, DARK.ink));
    set_mode(Appearance::System);
    assert_eq!(mode(), Appearance::System);
}
