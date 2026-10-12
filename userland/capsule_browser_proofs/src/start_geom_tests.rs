// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The start page geometry the painter and the click handler share: what it
//! places stays apart and inside the page, and a scroll holds to its ends.

use crate::browser::ui::rect::Rect;
use crate::browser::ui::start_geom::{compute, fav_rect, pill_text, scrolled, MAX_FAVS};

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

#[test]
fn cards_sit_below_the_tiles_and_apart() {
    for w in [480, 700, 948, 1128, 1686, 2560] {
        for favs in [0, 1, 4, MAX_FAVS] {
            let g = compute(w, 640, favs, 0);
            let tiles_end = (0..g.favs).map(|i| fav_rect(&g, i).bottom()).max().unwrap_or(0);
            for (i, a) in g.cards.iter().enumerate() {
                assert!(a.y >= tiles_end && a.y >= g.hero.bottom(), "{w} {favs}");
                assert!(a.x >= 0 && a.right() <= w, "{w} {favs}: {a:?}");
                for b in &g.cards[i + 1..] {
                    assert!(!overlap(*a, *b), "{w} {favs}: {a:?} vs {b:?}");
                }
            }
        }
    }
}

#[test]
fn the_pill_sits_in_the_hero_under_the_greeting() {
    for w in [480, 948, 1686] {
        let g = compute(w, 640, 4, 0);
        assert!(g.pill.y > g.sub_y && g.sub_y > g.greet_y && g.greet_y >= 0, "{w}");
        assert!(g.pill.bottom() <= g.hero.bottom() && g.pill.right() <= w, "{w}");
    }
}

#[test]
fn favourites_are_capped_and_tiles_never_overlap() {
    let g = compute(1200, 640, 50, 0);
    assert_eq!(g.favs, MAX_FAVS);
    for i in 0..g.favs {
        for j in i + 1..g.favs {
            assert!(!overlap(fav_rect(&g, i), fav_rect(&g, j)), "{i} {j}");
        }
    }
}

#[test]
fn a_scroll_holds_between_the_top_and_the_last_card() {
    let (w, h) = (948, 500);
    let top = scrolled(w, h, 8, -400);
    assert_eq!(top, compute(w, h, 8, 0));
    let end = scrolled(w, h, 8, i32::MAX / 2);
    assert_eq!(end.cards[2].bottom() + 32, h);
    assert_eq!(scrolled(w, h, 8, 120).hero.y, -120);
    let tall = scrolled(w, 4000, 8, 300);
    assert_eq!(tall.hero.y, 0, "a page that fits does not scroll");
}

#[test]
fn the_pill_text_is_gone_once_scrolled_past_the_top() {
    let g = scrolled(948, 500, 8, 0);
    assert!(pill_text(&g).is_some());
    let past = scrolled(948, 500, 8, g.pill.y + 1);
    assert_eq!(pill_text(&past), None);
    assert_eq!(pill_text(&compute(40, 500, 0, 0)), None, "too narrow for text");
}
