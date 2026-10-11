// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The list pages' geometry: rows and pills hit where they are drawn, scroll
//! moves both together, and nothing under the header band hits.

use crate::browser::ui::list_geom::{max_scroll, trail, ListGeom, BAND_H};
use crate::browser::ui::rect::Rect;

fn centre(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

#[test]
fn row_at_the_centre_of_each_row_is_that_row() {
    for w in [400, 800, 1600] {
        let g = ListGeom::new(w, 900, 0);
        for i in 0..10 {
            let (x, y) = centre(g.row_rect(i));
            assert_eq!(g.row_at(x, y, 10), Some(i), "{w} row {i}");
        }
    }
}

#[test]
fn nothing_hits_above_the_first_row_or_past_the_list() {
    let g = ListGeom::new(1000, 900, 0);
    let first = g.row_rect(0);
    for y in 0..first.y {
        assert_eq!(g.row_at(first.x + 10, y, 5), None, "y {y}");
    }
    let (x, y) = centre(g.row_rect(5));
    assert_eq!(g.row_at(x, y, 5), None);
    assert_eq!(g.row_at(g.frame.x - 1, first.y + 5, 5), None);
    assert_eq!(g.row_at(g.frame.right(), first.y + 5, 5), None);
}

#[test]
fn scroll_shifts_rows_and_hits_together() {
    let base = ListGeom::new(1000, 600, 0);
    for s in [0, 30, 56, 200, 1000] {
        let g = ListGeom::new(1000, 600, s);
        for i in 0..30 {
            let r = g.row_rect(i);
            assert_eq!(r.y, base.row_rect(i).y - s);
            let (x, y) = centre(r);
            let want = (y >= BAND_H).then_some(i);
            assert_eq!(g.row_at(x, y, 30), want, "scroll {s} row {i}");
        }
    }
    assert_eq!(ListGeom::new(1000, 600, -40), base);
}

#[test]
fn pills_hit_where_they_are_drawn() {
    let g = ListGeom::new(1000, 600, 300);
    let widths = [60, 90, 75];
    for i in 0..3 {
        let (x, y) = centre(g.pill(&widths, i));
        assert_eq!(g.pill_at(&widths, x, y), Some(i));
    }
    assert!(!overlap(g.pill(&widths, 0), g.pill(&widths, 1)));
    assert_eq!(g.pill_at(&widths, g.frame.x - 1, g.pills_y + 5), None);
}

#[test]
fn trail_sits_inside_its_row_and_scroll_is_bounded() {
    let g = ListGeom::new(1000, 600, 0);
    let r = g.row_rect(2);
    let t = trail(r);
    assert!(t.x > r.x && t.right() <= r.right() && t.y >= r.y && t.bottom() <= r.bottom());
    assert_eq!(max_scroll(500, 600), 0);
    assert_eq!(max_scroll(g.list_h(20), 600), g.list_h(20) - 600);
}
