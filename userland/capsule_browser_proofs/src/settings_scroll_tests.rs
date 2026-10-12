// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The settings page's sections: each card holds its rows, scroll moves
//! drawing and hits together, and nothing under the header band hits.

use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::{Kind, SettingsGeom, BAND_H};

use super::settings_geom_tests::{centre, controls};

#[test]
fn each_card_holds_its_rows() {
    let g = SettingsGeom::new(1000, 4000, 0);
    let cards: Vec<Rect> =
        g.items.iter().filter(|it| it.kind == Kind::Card).map(|it| it.rect).collect();
    assert_eq!(cards.len(), 7);
    for (c, r) in controls(&g) {
        assert!(cards.iter().any(|k| k.contains(r.x, r.y) && r.bottom() <= k.bottom()), "{c:?}");
    }
    for pair in cards.windows(2) {
        assert!(pair[0].bottom() < pair[1].y);
    }
    let last = cards[6].bottom();
    assert!(g.height > last && g.height - last < 80, "{} {}", g.height, last);
}

#[test]
fn scroll_moves_drawing_and_hits_together() {
    let (top, moved) = (SettingsGeom::new(900, 700, 0), SettingsGeom::new(900, 700, 150));
    assert_eq!(top.height, moved.height);
    for ((c, a), (d, b)) in controls(&top).into_iter().zip(controls(&moved)) {
        assert_eq!((c, b), (d, Rect::new(a.x, a.y - 150, a.w, a.h)));
        let (x, y) = centre(b);
        let want = if y >= BAND_H { Some(c) } else { None };
        assert_eq!(moved.hit(x, y), want, "{c:?}");
    }
}

#[test]
fn nothing_under_the_header_band_hits() {
    let g = SettingsGeom::new(900, 700, 400);
    for (_, r) in controls(&g) {
        for y in r.y.max(0)..r.bottom().min(BAND_H) {
            assert_eq!(g.hit(r.x + 1, y), None);
        }
    }
    assert_eq!(SettingsGeom::new(900, 700, 0).hit(450, BAND_H - 1), None);
}
