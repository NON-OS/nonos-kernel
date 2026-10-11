// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The toolbar geometry: one function places every button, the address pill,
//! its route badge and its text box, and the painter, the click handler, the
//! caret and the damage map all read it.

use crate::browser::omnibox::geometry::{pill_rect, pill_text, Rect as Px, NOTICE_W};
use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::limits::TOOLBAR_H;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::toolbar_geom::{buttons, hit, Part};

fn overlap(a: Rect, b: Rect) -> bool {
    a.w > 0
        && a.h > 0
        && b.w > 0
        && b.h > 0
        && a.x < b.right()
        && b.x < a.right()
        && a.y < b.bottom()
        && b.y < a.bottom()
}

fn inside(inner: Rect, outer: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.right() <= outer.right()
        && inner.bottom() <= outer.bottom()
}

#[test]
fn toolbar_parts_do_not_overlap_and_stay_inside() {
    for w in [700, 900, 1360, 2560] {
        let bar = compute(w, 700, SidebarMode::Hidden).toolbar;
        let g = buttons(bar);
        let parts = [g.back, g.fwd, g.reload, g.home, g.pill, g.star, g.sidebar];
        for (i, a) in parts.iter().enumerate() {
            assert!(inside(*a, bar), "{w}: part {i} outside");
            for b in &parts[i + 1..] {
                assert!(!overlap(*a, *b), "{w}: {a:?} overlaps {b:?}");
            }
        }
        assert!(inside(g.route, g.pill) && inside(g.text, g.pill));
        assert!(!overlap(g.text, g.route), "{w}: the text runs under the badge");
    }
}

#[test]
fn the_address_pill_is_at_least_200_wide_at_700() {
    assert!(buttons(Rect::new(0, 0, 700, TOOLBAR_H)).pill.w >= 200);
}

#[test]
fn toolbar_hit_agrees_with_every_part_centre() {
    let g = buttons(Rect::new(0, 0, 1000, TOOLBAR_H));
    let parts = [
        (g.back, Part::Back),
        (g.fwd, Part::Fwd),
        (g.reload, Part::Reload),
        (g.home, Part::Home),
        (g.route, Part::Route),
        (g.star, Part::Star),
        (g.sidebar, Part::Sidebar),
    ];
    for (r, p) in parts {
        assert_eq!(hit(&g, r.x + r.w / 2, r.y + r.h / 2), Some(p));
    }
    assert_eq!(hit(&g, g.pill.x + 4, g.pill.y + 4), Some(Part::Pill));
    assert_eq!(hit(&g, g.pill.x - 1, g.pill.y + 4), None);
}

#[test]
fn the_omnibox_reads_the_pill_the_toolbar_draws() {
    for w in [0, 120, 700, 1336, 2560] {
        let bar = compute(w, 700, SidebarMode::Hidden).toolbar;
        let g = buttons(bar);
        assert_eq!(pill_rect(bar), Px::from(g.pill), "{w}");
        assert_eq!(pill_text(bar, false), Px::from(g.text), "{w}");
        let cut = pill_text(bar, true);
        assert_eq!((cut.x, cut.w), (g.text.x as u32, (g.text.w as u32).saturating_sub(NOTICE_W)));
    }
}
