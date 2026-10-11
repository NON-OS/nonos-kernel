// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The window layout: a 56 px toolbar across the top of the app surface,
//! the sidebar and the page below it, tiling the surface exactly.

use crate::browser::ui::layout::{compute, Layout, SidebarMode};
use crate::browser::ui::limits::TOOLBAR_H;
use crate::browser::ui::rect::Rect;

fn area(r: Rect) -> i64 {
    r.w.max(0) as i64 * r.h.max(0) as i64
}

fn overlap(a: Rect, b: Rect) -> bool {
    let empty = a.w <= 0 || a.h <= 0 || b.w <= 0 || b.h <= 0;
    !empty && a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

fn inside(inner: Rect, outer: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.right() <= outer.right()
        && inner.bottom() <= outer.bottom()
}

#[test]
fn hidden_gives_the_page_the_whole_width() {
    let l = compute(1360, 700, SidebarMode::Hidden);
    assert_eq!((l.sidebar.w, l.content.x, l.content.w), (0, 0, 1360));
    assert!(!l.sidebar.contains(0, 100));
}

#[test]
fn toolbar_is_56_tall_and_content_starts_under_it() {
    for (w, h) in [(1360, 700), (900, 600), (500, 400), (2560, 1440)] {
        let l = compute(w, h, SidebarMode::Hidden);
        assert_eq!((l.toolbar.h, l.content.y, l.sidebar.y), (TOOLBAR_H, 56, 56));
        assert_eq!(l.toolbar, Rect::new(0, 0, w, 56));
    }
}

#[test]
fn the_three_rects_tile_the_buffer_without_overlap() {
    for w in (0..2000).step_by(37) {
        for h in (0..900).step_by(29) {
            let l = compute(w, h, SidebarMode::Hidden);
            let full = Rect::new(0, 0, w, h);
            let parts = [l.toolbar, l.sidebar, l.content];
            assert!(parts.iter().all(|p| inside(*p, full)), "{w}x{h}");
            assert_eq!(parts.iter().map(|p| area(*p)).sum::<i64>(), area(full));
            assert!(!overlap(l.toolbar, l.sidebar) && !overlap(l.toolbar, l.content));
            assert!(!overlap(l.sidebar, l.content), "{w}x{h}");
            assert_eq!(l.content.w + l.sidebar.w, w);
        }
    }
}

#[test]
fn degenerate_sizes_give_an_empty_toolbar_or_page() {
    assert_eq!(compute(0, 0, SidebarMode::Hidden), Layout::default());
    assert_eq!(compute(-50, -9, SidebarMode::Hidden), Layout::default());
    let l = compute(800, 30, SidebarMode::Hidden);
    assert_eq!((l.toolbar.h, l.content.h, l.content.y), (30, 0, 30));
}

#[test]
fn rect_basics() {
    let r = Rect::new(10, 20, 30, 40);
    assert_eq!((r.right(), r.bottom()), (40, 60));
    assert!(r.contains(10, 20) && !r.contains(40, 20) && !r.contains(10, 60));
    assert_eq!(r.inset(5), Rect::new(15, 25, 20, 30));
    assert_eq!(r.inset(100).w, 0);
    assert!(!Rect::new(0, 0, 0, 10).contains(0, 0));
    assert_eq!(Rect::new(i32::MAX, 0, 10, 10).right(), i32::MAX);
}
