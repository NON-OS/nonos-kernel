// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The reader settings card: every control hits where it is drawn, inside
//! the card and apart, and a card too narrow to draw hits nothing.

use crate::browser::ui::reader_geom::{panel, ReaderGeom, MARGIN, MIN_W, PANEL_W};
use crate::browser::ui::reader_hit::{hit, Control};
use crate::browser::ui::rect::Rect;

fn centre(r: Rect) -> (i32, i32) {
    (r.x + r.w / 2, r.y + r.h / 2)
}

fn controls(g: &ReaderGeom) -> Vec<(Rect, Control)> {
    let mut v =
        vec![(g.close, Control::Close), (g.minus, Control::Smaller), (g.plus, Control::Larger)];
    v.extend((0..3).map(|i| (g.swatches[i], Control::Theme(i as u8))));
    v.extend((0..3).map(|i| (g.widths[i], Control::Width(i as u8))));
    v.push((g.switch, Control::Time));
    v
}

fn inside(r: Rect, o: Rect) -> bool {
    r.x >= o.x && r.y >= o.y && r.right() <= o.right() && r.bottom() <= o.bottom()
}

#[test]
fn every_control_hits_at_its_centre() {
    for w in [MIN_W + 2 * MARGIN, 400, 700, 1400] {
        let g = panel(w);
        for (r, c) in controls(&g) {
            let (x, y) = centre(r);
            assert_eq!(hit(&g, x, y), Some(c), "{w}: {c:?}");
        }
    }
}

#[test]
fn controls_sit_in_the_panel_and_do_not_overlap() {
    for w in (MIN_W + 2 * MARGIN..1600).step_by(17) {
        let g = panel(w);
        assert!(g.panel.right() <= w - MARGIN && g.panel.x >= 0 && g.panel.w <= PANEL_W);
        let c = controls(&g);
        for (i, (a, _)) in c.iter().enumerate() {
            assert!(inside(*a, g.panel), "{w}: {a:?}");
            for (b, _) in c.iter().skip(i + 1).filter(|(_, k)| *k != Control::Time) {
                let apart =
                    a.right() <= b.x || b.right() <= a.x || a.bottom() <= b.y || b.bottom() <= a.y;
                assert!(apart || *a == g.switch, "{w}: {a:?} {b:?}");
            }
        }
        assert!(inside(g.switch, g.time));
    }
}

#[test]
fn the_time_row_works_the_switch_and_dots_do_nothing() {
    let g = panel(1000);
    assert_eq!(hit(&g, g.time.x + 2, g.time.y + 2), Some(Control::Time));
    let (x, y) = centre(g.dots);
    assert_eq!(hit(&g, x, y), None);
    assert_eq!(hit(&g, g.panel.x - 1, g.panel.y + 5), None);
}

#[test]
fn a_card_too_narrow_to_draw_hits_nothing() {
    for w in [0, -10, 100, MIN_W + 2 * MARGIN - 1] {
        let g = panel(w);
        assert!(g.panel.w < MIN_W);
        for (r, _) in controls(&g) {
            let (x, y) = centre(r);
            assert_eq!(hit(&g, x, y), None);
        }
    }
}
