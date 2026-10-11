// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! What a new window shows, and the start page shown over a loaded tab.

use crate::browser::shell::{Page, Shell};
use crate::browser::ui::layout::SidebarMode;

#[test]
fn a_new_window_shows_the_tab_with_the_sidebar_on_auto() {
    let s = Shell::default();
    assert_eq!((s.page, s.sidebar, s.page_scroll), (Page::Web, SidebarMode::Auto, 0));
    assert!(s.showing_start(true) && !s.showing_start(false));
}

#[test]
fn the_start_page_shows_over_a_loaded_tab_from_its_top() {
    let mut s = Shell { page_scroll: 300, ..Shell::default() };
    s.show(Page::Start);
    assert!(s.showing_start(false) && s.showing_start(true));
    assert_eq!(s.page_scroll, 0);
    s.show(Page::Web);
    assert!(!s.showing_start(false));
}
