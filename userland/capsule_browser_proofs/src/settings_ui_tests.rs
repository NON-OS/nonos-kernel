// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Remove all bookmarks takes two clicks in a row, and once done leaves
//! tombstones so another window's save does not bring them back; leaving
//! the settings page lets go of its field and disarms the button.

use crate::browser::shell::settings_ui::{press, Press};
use crate::browser::shell::{Page, Shell};
use crate::browser::ui::settings_rows::Field;

use super::codec_fixture::mark;

#[test]
fn the_first_click_arms_the_second_clears_and_none_does_nothing() {
    assert_eq!(press(false, 3), Press::Arm);
    assert_eq!(press(true, 3), Press::Clear);
    assert_eq!(press(false, 0), Press::Nothing);
    assert_eq!(press(true, 0), Press::Nothing);
}

#[test]
fn removing_every_bookmark_leaves_one_tombstone_each() {
    let mut s = Shell::default();
    s.bookmarks = vec![mark("https://a.com/", "A", 1), mark("https://b.org/", "B", 2)];
    s.removed_bookmarks = vec!["https://a.com/".into()];
    s.remove_all_bookmarks();
    assert!(s.bookmarks.is_empty());
    assert_eq!(s.removed_bookmarks, ["https://a.com/", "https://b.org/"]);
}

#[test]
fn showing_a_page_settles_the_settings_page() {
    let mut s = Shell::default();
    s.settings.focus = Some(Field::Search);
    s.settings.armed = true;
    s.show(Page::Settings);
    assert_eq!((s.page, s.settings.focus, s.settings.armed), (Page::Settings, None, false));
}

#[test]
fn a_refill_puts_the_text_back_and_drops_the_refusal() {
    let mut s = Shell::default();
    s.settings.search_err = Some("no");
    s.settings.refill(Field::Search, "https://x.org/%s");
    assert_eq!(s.settings.search.text, "https://x.org/%s");
    assert_eq!(s.settings.search.caret, s.settings.search.text.len());
    assert_eq!(s.settings.search_err, None);
}
