// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The toolbar and home page are hit-tested at the width they are painted.
//! A fixed 1360 put the menu at x >= 1316 and the badges 90 px off at 1202.

use crate::browser::omnibox::geometry::{pill_rect, BADGE, BADGE_Y};
use crate::browser::omnibox::{center_x, search_bar_hit, shortcut_at};
use crate::browser::ui::limits::TOOLBAR_H;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::{buttons, hit, Part};

#[test]
fn toolbar_buttons_follow_the_width() {
    let y = TOOLBAR_H / 2;
    for w in [1180, 1338, 1918] {
        let bar = Rect::new(0, 0, w, TOOLBAR_H);
        let g = buttons(bar);
        assert_eq!(hit(&g, w - 20, y), Some(Part::Menu), "menu at {w}");
        assert_eq!(hit(&g, w - 70, y), Some(Part::Route), "badge at the pill end at {w}");
        assert_eq!(hit(&g, w - 160, y), Some(Part::Pill), "pill left of the badge at {w}");
        assert_eq!(hit(&g, w + 5, y), None, "past the edge at {w}");
        assert_eq!(hit(&g, 20, y), Some(Part::Back));
        assert_eq!(hit(&g, 70, y), Some(Part::Fwd));
        assert_eq!(hit(&g, 110, y), Some(Part::Reload));
        assert_eq!(hit(&g, 160, y), Some(Part::Home));
        let p = pill_rect(bar);
        assert_eq!(p.x + p.w, w as u32 - 60);
    }
    let g = buttons(Rect::new(0, 0, 1918, TOOLBAR_H));
    assert_eq!(hit(&g, 1320, y), Some(Part::Pill), "not the menu");
    assert_eq!(hit(&g, 20, g.back.y - 1), None, "above the button");
    assert_eq!(hit(&g, 20, g.back.bottom() - 1), Some(Part::Back), "its last row");
    assert_eq!(hit(&g, 20, g.back.bottom()), None, "below the button");
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
