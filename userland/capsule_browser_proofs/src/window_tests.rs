// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! What a new window shows, and the start page shown over a loaded tab.

use crate::browser::shell::kept::{Group, ReaderPrefs};
use crate::browser::shell::store::Persisted;
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

#[test]
fn every_page_but_the_tabs_own_is_drawn_by_the_window() {
    let mut s = Shell::default();
    assert!(!s.own_page(false) && s.own_page(true));
    for p in
        [Page::Start, Page::Tabs, Page::Bookmarks, Page::Downloads, Page::History, Page::Reader]
    {
        s.show(p);
        assert!(s.own_page(false), "{p:?}");
    }
}

#[test]
fn showing_a_page_drops_a_rename_in_progress() {
    let mut s = Shell { rename: Some("half typed".into()), ..Shell::default() };
    s.show(Page::Tabs);
    assert_eq!(s.rename, None);
}

#[test]
fn apply_keeps_the_first_of_a_doubled_group_and_clamps_the_reader() {
    let g = |id, name: &str| Group { id, name: name.into(), color: 0 };
    let reader = ReaderPrefs { theme: 7, size: 200, width: 3, show_time: false };
    let p =
        Persisted { groups: vec![g(1, "a"), g(1, "b"), g(2, "c")], reader, ..Default::default() };
    let mut s = Shell::default();
    s.apply(p);
    let names: Vec<&str> = s.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["a", "c"]);
    assert_eq!(s.reader, ReaderPrefs { theme: 2, size: 4, width: 2, show_time: false });
}
