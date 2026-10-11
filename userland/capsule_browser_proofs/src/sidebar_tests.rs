// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The sidebar rows: one geometry places them for the painter and the click
//! handler, inside the sidebar, apart, and Settings held to the bottom.

use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::rect::Rect;
use crate::browser::ui::sidebar_geom::{hit, rows, Row, RowKind};

fn side(rail: bool, h: i32) -> Rect {
    let mode = if rail { SidebarMode::Rail } else { SidebarMode::Full };
    compute(1400, h, mode).sidebar
}

fn cases() -> impl Iterator<Item = (bool, Rect)> {
    [false, true]
        .into_iter()
        .flat_map(|rail| (300..=1400).step_by(7).map(move |h| (rail, side(rail, h))))
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

fn inside(r: Rect, s: Rect) -> bool {
    r.x >= s.x && r.y >= s.y && r.right() <= s.right() && r.bottom() <= s.bottom()
}

fn settings(r: &[Row]) -> Rect {
    r.iter().find(|r| r.kind == RowKind::Settings).expect("settings row").rect
}

#[test]
fn rows_lie_inside_the_sidebar_and_never_overlap() {
    for (rail, s) in cases() {
        let r = rows(rail, s);
        assert_eq!(
            r.iter().map(|r| r.kind).collect::<Vec<_>>(),
            [RowKind::Start, RowKind::Settings]
        );
        for (i, a) in r.iter().enumerate() {
            assert!(inside(a.rect, s) && a.rect.w > 0, "{rail} {s:?}: {a:?}");
            for b in &r[i + 1..] {
                assert!(!overlap(a.rect, b.rect), "{rail} {s:?}: {a:?} vs {b:?}");
            }
        }
    }
}

#[test]
fn settings_is_anchored_to_the_bottom() {
    for (rail, s) in cases() {
        let r = rows(rail, s);
        let st = settings(&r);
        assert_eq!(st.bottom(), s.bottom() - 12, "{rail} {s:?}");
        assert!(r.iter().all(|o| o.kind == RowKind::Settings || o.rect.bottom() <= st.y));
    }
}

#[test]
fn hit_agrees_with_rows_at_every_centre() {
    for (rail, s) in cases() {
        for row in rows(rail, s) {
            let (x, y) = (row.rect.x + row.rect.w / 2, row.rect.y + row.rect.h / 2);
            assert_eq!(hit(rail, s, x, y), Some(row.kind), "{rail} {s:?}");
        }
        assert_eq!(hit(rail, s, s.right(), s.y + 100), None);
        assert_eq!(hit(rail, s, s.x + 1, s.y - 1), None);
    }
}
