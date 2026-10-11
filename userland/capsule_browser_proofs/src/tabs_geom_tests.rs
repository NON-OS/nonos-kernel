// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The titlebar tab strip's geometry, which its painter and its hit-test
//! share.

use crate::browser::ui::rect::Rect;
use crate::browser::ui::tabs_geom::{
    nominal_w, plus_rect, tab_rect, visible, Strip, PLUS, TAB_MIN, TAB_W,
};

pub(crate) fn strips() -> impl Iterator<Item = Strip> {
    (1..=6usize).flat_map(|n| {
        (0..n).flat_map(move |active| {
            (PLUS + TAB_MIN + 4..=1600).step_by(13).map(move |w| Strip { n, active, w, h: 40 })
        })
    })
}

pub(crate) fn shown(s: &Strip) -> Vec<(usize, Rect)> {
    (0..s.n).filter_map(|i| tab_rect(s, i).map(|r| (i, r))).collect()
}

#[test]
fn tabs_never_overlap_each_other_or_the_plus() {
    for s in strips() {
        let tabs = shown(&s);
        let plus = plus_rect(&s);
        for (k, (_, r)) in tabs.iter().enumerate() {
            assert!(r.right() <= plus.x, "{s:?}: tab {r:?} reaches plus {plus:?}");
            if let Some((_, next)) = tabs.get(k + 1) {
                assert!(r.right() <= next.x, "{s:?}");
            }
        }
    }
}

#[test]
fn everything_lies_inside_the_strip() {
    for s in strips() {
        for (_, r) in shown(&s) {
            assert!(r.x >= 0 && r.right() <= s.w && r.y >= 0 && r.bottom() <= s.h, "{s:?}");
        }
        let p = plus_rect(&s);
        assert!(p.x >= 0 && p.right() <= s.w, "{s:?}: plus {p:?}");
        assert_eq!(p.w, PLUS);
    }
}

#[test]
fn shown_tabs_stay_between_min_and_full_width() {
    for s in strips() {
        for (_, r) in shown(&s) {
            assert!((TAB_MIN..=TAB_W).contains(&r.w), "{s:?}: width {}", r.w);
        }
    }
}

#[test]
fn six_tabs_at_700_shrink_and_cap_the_visible_count() {
    for active in 0..6 {
        let s = Strip { n: 6, active, w: 700, h: 40 };
        let (first, count) = visible(&s);
        assert_eq!(count, 5);
        assert!((first..first + count).contains(&active), "active {active} hidden");
        assert!(shown(&s).iter().all(|(_, r)| r.w >= TAB_MIN && r.w < TAB_W));
    }
}

#[test]
fn a_wide_strip_shows_every_tab_at_full_width() {
    let s = Strip { n: 6, active: 0, w: nominal_w(6), h: 40 };
    assert_eq!(visible(&s), (0, 6));
    assert!(shown(&s).iter().all(|(_, r)| r.w == TAB_W));
}
