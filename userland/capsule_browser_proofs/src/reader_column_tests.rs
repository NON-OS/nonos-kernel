// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The reader's article column: beside the settings card while that leaves
//! it room, widening with the width choice, inside a narrow content area.

use crate::browser::ui::reader_column::{column, MIN_COLUMN, WIDE_MIN};
use crate::browser::ui::reader_geom::panel;

#[test]
fn the_column_stays_left_of_the_card_on_wide_screens() {
    for w in (WIDE_MIN..2600).step_by(23) {
        for width in 0..4u8 {
            let (x, cw) = column(w, width);
            assert!(x >= 0 && cw > 0 && x + cw <= panel(w).panel.x, "{w} {width}");
        }
    }
}

#[test]
fn the_column_widens_with_the_width_choice_and_fits_narrow_screens() {
    let (_, a) = column(2400, 0);
    let (_, b) = column(2400, 1);
    let (_, c) = column(2400, 2);
    assert!(a < b && b < c);
    assert_eq!(column(2400, 9), column(2400, 2));
    for w in 0..WIDE_MIN {
        let (x, cw) = column(w, 2);
        assert!(x >= 0 && cw >= 0 && x + cw <= w.max(0), "{w}");
    }
}

#[test]
fn the_card_sits_beside_a_column_it_leaves_room_for() {
    for w in (WIDE_MIN..1400).step_by(7) {
        for width in 0..3u8 {
            let (x, cw) = column(w, width);
            assert!(cw >= MIN_COLUMN && x + cw <= panel(w).panel.x, "{w} {width}");
        }
    }
    let (x, cw) = column(872, 1);
    assert!((MIN_COLUMN..680).contains(&cw) && x + cw <= panel(872).panel.x);
}
