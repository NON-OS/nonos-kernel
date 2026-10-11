// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Repaints cover what changed. A keystroke in the address bar used to
//! repaint about 935k pixels to change the 43k of the pill.

use crate::browser::omnibox::geometry::{pill_rect, search_rect, Rect};
use crate::browser::ui::layout::{compute, SidebarMode};
use crate::browser::ui::limits::TOOLBAR_H;

const TOP: u32 = TOOLBAR_H as u32;
const PAGE: Rect = Rect { x: 0, y: TOP, w: 1336, h: 700 - TOP };
use crate::browser::omnibox::parts::damage_for;
use crate::browser::omnibox::{bits, rect_of, Change, Damage};

fn surface() -> crate::browser::ui::layout::Layout {
    compute(1336, 700, SidebarMode::Hidden)
}

#[test]
fn a_keystroke_damages_only_the_pill() {
    let r = damage_for(Change::OmniboxEdit, 1336, 700).expect("partial");
    assert_eq!(r, pill_rect(surface().toolbar));
    assert!(r.w * r.h < 45_000, "pill is {} px", r.w * r.h);
}

#[test]
fn parts_combine_and_full_means_whole_window() {
    let home = damage_for(Change::HomeEdit, 1336, 700).expect("partial");
    assert_eq!(home, pill_rect(surface().toolbar).union(search_rect(1336).within(PAGE)));
    let page = damage_for(Change::Scroll, 1336, 700).expect("partial");
    assert_eq!(page, PAGE);
    let bubble = damage_for(Change::Bubble, 1336, 700).expect("partial");
    assert_eq!((bubble.y, bubble.h), (676, 24));
    assert_eq!(damage_for(Change::Full, 1336, 700), None);
    assert_eq!(rect_of(Damage::default(), &surface()), None, "nothing recorded");
    let mut d = bits(Change::OmniboxEdit);
    d.add(bits(Change::Full));
    assert_eq!(rect_of(d, &surface()), None);
}

#[test]
fn a_bubble_repaint_commits_every_row_it_draws() {
    use crate::browser::omnibox::geometry::band_commit;
    /* The band grown over a picture crossing it: rows 300..676 of the view. */
    assert_eq!(band_commit(Some((300, 676)), PAGE), Rect { x: 0, y: TOP + 300, w: 1336, h: 376 });
    /* A page the band cannot be painted alone in repaints, and commits, whole. */
    assert_eq!(band_commit(None, PAGE), PAGE);
    assert_eq!(band_commit(Some((-5, 20)), PAGE).y, TOP, "clamped to the view");
}
