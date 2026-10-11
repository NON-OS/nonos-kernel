// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Where a click in the tab strip lands, and that the tab in view always
//! has a place there.

use crate::browser::ui::rect::Rect;
use crate::browser::ui::tabs_geom::{close_rect, plus_rect, tab_rect, Strip};
use crate::browser::ui::tabs_hit::{hit, TabHit};
use crate::tabs_geom_tests::{shown, strips};

fn centre(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

#[test]
fn hit_on_the_close_box_closes_and_elsewhere_selects() {
    for s in strips() {
        for (i, r) in shown(&s) {
            let (cx, cy) = centre(close_rect(r));
            assert_eq!(hit(&s, cx, cy), Some(TabHit::Close(i)), "{s:?}");
            assert_eq!(hit(&s, r.x + 4, r.y + r.h / 2), Some(TabHit::Tab(i)), "{s:?}");
            assert_eq!(hit(&s, r.x + r.w / 3, r.y + r.h / 2), Some(TabHit::Tab(i)), "{s:?}");
        }
        let (px, py) = centre(plus_rect(&s));
        assert_eq!(hit(&s, px, py), Some(TabHit::Plus));
    }
}

#[test]
fn close_box_sits_inside_its_tab() {
    for s in strips() {
        for (_, r) in shown(&s) {
            let c = close_rect(r);
            assert!(c.x >= r.x && c.right() <= r.right() && c.y >= r.y && c.bottom() <= r.bottom());
        }
    }
}

#[test]
fn a_miss_hits_nothing() {
    let s = Strip { n: 3, active: 0, w: 1200, h: 40 };
    assert_eq!(hit(&s, 1199, 20), None);
    assert_eq!(hit(&s, 10, 0), None);
    assert_eq!(hit(&s, -1, 20), None);
}

#[test]
fn the_active_tab_is_always_visible() {
    for s in strips() {
        assert!(tab_rect(&s, s.active).is_some(), "{s:?}");
    }
}
