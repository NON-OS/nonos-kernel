// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The toolbar and home page are hit-tested at the width they are painted.
//! A fixed 1360 put the menu at x >= 1316 and the badges 90 px off at 1202.

use crate::browser::omnibox::geometry::{pill_rect, BADGE, BADGE_Y};
use crate::browser::omnibox::{center_x, search_bar_hit, shortcut_at, toolbar_button_at, Btn};
use crate::browser::ui::limits::TOOLBAR_H;

#[test]
fn toolbar_buttons_follow_the_width() {
    let y = 20;
    for w in [1180u32, 1338, 1918] {
        let wi = w as i32;
        assert_eq!(toolbar_button_at(wi - 20, y, w), Some(Btn::Menu), "menu at {w}");
        assert_eq!(toolbar_button_at(wi - 60, y, w), Some(Btn::Url), "pill end at {w}");
        assert_eq!(toolbar_button_at(wi + 5, y, w), None, "past the edge at {w}");
        assert_eq!(toolbar_button_at(20, y, w), Some(Btn::Back));
        assert_eq!(toolbar_button_at(50, y, w), Some(Btn::Forward));
        assert_eq!(toolbar_button_at(90, y, w), Some(Btn::Reload));
        assert_eq!(toolbar_button_at(120, y, w), Some(Btn::Home));
        let p = pill_rect(w);
        assert_eq!(p.x + p.w, w - 52);
    }
    assert_eq!(toolbar_button_at(1320, y, 1918), Some(Btn::Url), "not the menu");
    assert_eq!(toolbar_button_at(20, -1, 1918), None, "above the toolbar");
    assert_eq!(toolbar_button_at(20, TOOLBAR_H - 1, 1918), Some(Btn::Back), "its last row");
    assert_eq!(toolbar_button_at(20, TOOLBAR_H, 1918), None, "below the toolbar");
}

#[test]
fn shortcuts_and_search_bar_follow_the_width() {
    let y = (BADGE_Y + BADGE / 2) as i32;
    for w in [1180u32, 1338, 1918] {
        for i in 0..4u32 {
            let x = center_x(w, 4, i) as i32;
            assert_eq!(shortcut_at(x, y, w, 4), Some(i as usize), "badge {i} at {w}");
        }
        let left = center_x(w, 4, 0) as i32 - BADGE as i32;
        assert_eq!(shortcut_at(left, y, w, 4), None);
        assert!(search_bar_hit(w as i32 / 2, 190, w));
        assert!(!search_bar_hit(10, 190, w));
    }
}
