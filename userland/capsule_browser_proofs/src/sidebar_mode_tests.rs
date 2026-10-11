// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The sidebar modes: Auto picks Full or Rail by width, every mode folds to
//! a narrower one before it starves the page, and the button cycles them.

use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::limits::{MIN_CONTENT_W, SIDEBAR_FULL, SIDEBAR_RAIL};
use crate::browser::ui::rect::Rect;

const MODES: [SidebarMode; 4] =
    [SidebarMode::Auto, SidebarMode::Full, SidebarMode::Rail, SidebarMode::Hidden];

fn area(r: Rect) -> i64 {
    r.w.max(0) as i64 * r.h.max(0) as i64
}

#[test]
fn auto_is_full_wide_the_rail_narrower_and_hidden_on_a_narrow_window() {
    let at = |w, h| compute(w, h, SidebarMode::Auto);
    let (full, rail, none) = (at(1360, 700), at(900, 600), at(500, 400));
    assert_eq!((full.sidebar.w, full.content.x, full.rail), (SIDEBAR_FULL, 232, false));
    assert_eq!((rail.sidebar.w, rail.content.x, rail.rail), (SIDEBAR_RAIL, 64, true));
    assert_eq!((none.sidebar.w, none.content.x, none.rail), (0, 0, false));
    assert!(!none.sidebar.contains(0, 100));
}

#[test]
fn every_mode_tiles_the_surface_under_the_toolbar() {
    for w in (0..2000).step_by(37) {
        for h in (0..900).step_by(29) {
            for m in MODES {
                let l = compute(w, h, m);
                let sum = area(l.toolbar) + area(l.sidebar) + area(l.content);
                assert_eq!(sum, area(Rect::new(0, 0, w, h)));
                assert_eq!((l.content.w + l.sidebar.w, l.content.x), (w, l.sidebar.right()));
                assert_eq!((l.sidebar.y, l.content.y), (l.toolbar.h, l.toolbar.h), "{w}x{h} {m:?}");
                assert_eq!(l.rail, l.sidebar.w == SIDEBAR_RAIL);
            }
        }
    }
}

#[test]
fn a_sidebar_never_leaves_the_content_too_narrow() {
    for w in 0..2200 {
        for m in MODES {
            let l = compute(w, 700, m);
            assert!(l.sidebar.w == 0 || l.content.w >= MIN_CONTENT_W, "{w} {m:?}");
        }
    }
}

/* Full asked for on a narrow window falls back Full, Rail, Hidden: it keeps
 * the widest sidebar that still leaves MIN_CONTENT_W of content. */
#[test]
fn forced_full_is_honoured_until_it_would_starve_the_content() {
    assert_eq!(compute(900, 600, SidebarMode::Full).sidebar.w, SIDEBAR_FULL);
    assert_eq!(compute(712, 600, SidebarMode::Full).sidebar.w, SIDEBAR_FULL);
    assert_eq!(compute(711, 600, SidebarMode::Full).sidebar.w, SIDEBAR_RAIL);
    assert_eq!(compute(544, 600, SidebarMode::Full).sidebar.w, SIDEBAR_RAIL);
    assert_eq!(compute(543, 600, SidebarMode::Full).sidebar.w, 0);
    assert_eq!(compute(543, 600, SidebarMode::Rail).sidebar.w, 0);
    assert_eq!(compute(2000, 600, SidebarMode::Hidden).sidebar.w, 0);
    assert_eq!(compute(2000, 600, SidebarMode::Rail).sidebar.w, SIDEBAR_RAIL);
}

#[test]
fn the_sidebar_button_cycles_full_rail_hidden() {
    assert_eq!(SidebarMode::default(), SidebarMode::Auto);
    assert_eq!(SidebarMode::Auto.cycled(), SidebarMode::Rail);
    assert_eq!(SidebarMode::Full.cycled(), SidebarMode::Rail);
    assert_eq!(SidebarMode::Rail.cycled(), SidebarMode::Hidden);
    assert_eq!(SidebarMode::Hidden.cycled(), SidebarMode::Full);
}
