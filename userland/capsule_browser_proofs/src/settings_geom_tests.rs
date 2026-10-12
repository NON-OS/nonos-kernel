// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The settings page's geometry: every control hits where it is drawn at
//! any width, and nothing a row holds overlaps another or leaves the frame.

use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::{Control, Item, Kind, SettingsGeom};

const WIDTHS: [i32; 5] = [360, 400, 800, 1100, 1600];

pub fn centre(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

fn overlap(a: Rect, b: Rect) -> bool {
    a.x < b.right() && b.x < a.right() && a.y < b.bottom() && b.y < a.bottom()
}

pub fn controls(g: &SettingsGeom) -> Vec<(Control, Rect)> {
    let ctl = |it: &Item| match it.kind {
        Kind::Ctl(c) => Some((c, it.rect)),
        _ => None,
    };
    g.items.iter().filter_map(ctl).collect()
}

#[test]
fn every_control_hits_at_its_centre_at_every_width() {
    for w in WIDTHS {
        let g = SettingsGeom::new(w, 4000, 0);
        let all = controls(&g);
        assert!(all.len() >= 20, "{w}: {}", all.len());
        for (c, r) in all {
            assert!(r.w > 0 && r.h > 0, "{w} {c:?} {r:?}");
            let (x, y) = centre(r);
            assert_eq!(g.hit(x, y), Some(c), "{w} {c:?}");
            assert_eq!(g.rect(c), Some(r), "{w} {c:?}");
        }
    }
}

#[test]
fn nothing_but_cards_overlaps_and_all_sits_inside_the_frame() {
    for w in WIDTHS {
        let g = SettingsGeom::new(w, 4000, 0);
        let parts: Vec<_> = g.items.iter().filter(|it| it.kind != Kind::Card).collect();
        for (i, a) in parts.iter().enumerate() {
            assert!(a.rect.x >= g.frame.x && a.rect.right() <= g.frame.right(), "{w} {a:?}");
            for b in &parts[i + 1..] {
                let empty = a.rect.w == 0 || b.rect.w == 0;
                assert!(empty || !overlap(a.rect, b.rect), "{w}: {a:?} over {b:?}");
            }
        }
    }
}
