// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The sidebar's Tab Groups section: listed in the full sidebar as far as it
//! fits, never in the rail, with the dividers between rows and a short
//! sidebar pushing Settings down rather than over.

use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::rect::Rect;
use crate::browser::ui::sidebar_geom::{dividers, groups_head, rows, RowKind, ROWS};

fn side(rail: bool, h: i32) -> Rect {
    let mode = if rail { SidebarMode::Rail } else { SidebarMode::Full };
    compute(1400, h, mode).sidebar
}

fn cases() -> impl Iterator<Item = (bool, Rect, usize)> {
    [false, true].into_iter().flat_map(|rail| {
        (560..=1400).step_by(7).flat_map(move |h| [0, 3, 8].map(move |g| (rail, side(rail, h), g)))
    })
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

fn inside(r: Rect, s: Rect) -> bool {
    r.x >= s.x && r.y >= s.y && r.right() <= s.right() && r.bottom() <= s.bottom()
}

#[test]
fn the_rail_has_the_fixed_rows_only() {
    for (_, s, g) in cases().filter(|c| c.0) {
        let r = rows(true, s, g);
        assert_eq!(r.len(), ROWS);
        assert!(r.iter().all(|r| r.rect.w == r.rect.h));
        assert_eq!(groups_head(true, s, g), None);
    }
}

#[test]
fn the_full_sidebar_lists_the_first_groups_that_fit() {
    for (_, s, g) in cases().filter(|c| !c.0) {
        let r = rows(false, s, g);
        let shown: Vec<usize> = r
            .iter()
            .filter_map(|r| if let RowKind::Group(i) = r.kind { Some(i) } else { None })
            .collect();
        assert!(shown.len() <= g);
        assert_eq!(shown, (0..shown.len()).collect::<Vec<_>>());
        let section = r.iter().any(|r| r.kind == RowKind::AllTabs);
        assert_eq!(section, r.iter().any(|r| r.kind == RowKind::NewGroup));
        if let Some(head) = groups_head(false, s, g) {
            assert!(section && inside(head, s));
            assert!(r.iter().all(|o| !overlap(o.rect, head)), "{s:?} {g}");
        }
    }
    let tall = side(false, 1400);
    let r = rows(false, tall, 8);
    assert_eq!(r.len(), ROWS + 8 + 2);
}

#[test]
fn dividers_fall_between_rows() {
    for (rail, s, g) in cases() {
        let r = rows(rail, s, g);
        for d in dividers(rail, s, g) {
            assert!(d > s.y && d < s.bottom());
            assert!(r.iter().all(|o| d < o.rect.y || d >= o.rect.bottom()), "{rail} {s:?} {g}");
        }
    }
}

#[test]
fn a_short_sidebar_pushes_settings_down_rather_than_over() {
    for h in 0..560 {
        for rail in [false, true] {
            let s = Rect::new(0, 56, if rail { 64 } else { 232 }, h);
            let r = rows(rail, s, 8);
            for (i, a) in r.iter().enumerate() {
                for b in &r[i + 1..] {
                    assert!(!overlap(a.rect, b.rect), "{rail} h={h}");
                }
            }
        }
    }
}
