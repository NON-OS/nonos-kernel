// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The sidebar's brand, divider and short-window behaviour.

use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::rect::Rect;
use crate::browser::ui::sidebar_geom::{brand, divider, rows};

fn side(rail: bool, h: i32) -> Rect {
    let mode = if rail { SidebarMode::Rail } else { SidebarMode::Full };
    compute(1400, h, mode).sidebar
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

#[test]
fn the_rail_has_square_rows_and_no_brand() {
    for s in (300..=1400).step_by(7).map(|h| side(true, h)) {
        assert!(rows(true, s).iter().all(|r| r.rect.w == r.rect.h));
        assert_eq!(brand(true, s).h, 0);
    }
    let b = brand(false, side(false, 700));
    assert!(b.h > 0 && b.w > 0 && b.y >= 56);
}

#[test]
fn the_divider_falls_between_the_rows() {
    for (rail, h) in
        [false, true].into_iter().flat_map(|r| (300..=1400).step_by(7).map(move |h| (r, h)))
    {
        let s = side(rail, h);
        let r = rows(rail, s);
        let d = divider(rail, s);
        assert!(d > s.y && d < s.bottom());
        assert!(r.iter().all(|o| d < o.rect.y || d >= o.rect.bottom()), "{rail} {s:?}");
    }
}

#[test]
fn a_short_sidebar_pushes_settings_down_rather_than_over() {
    for h in 0..300 {
        for rail in [false, true] {
            let s = Rect::new(0, 56, if rail { 64 } else { 232 }, h);
            let r = rows(rail, s);
            assert!(!overlap(r[0].rect, r[1].rect), "{rail} h={h}");
            assert!(r[1].rect.y > r[0].rect.bottom(), "{rail} h={h}");
        }
    }
}
