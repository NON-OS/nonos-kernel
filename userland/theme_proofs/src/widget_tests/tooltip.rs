// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Tooltip: short, multi-byte and too long texts stay in the box in every
//! state at every scale, in boxes its own size, wider, narrower and shorter,
//! and every tooltip is one line tall and no wider than `TOOLTIP_MAX_W`.

use nonos_toolkit::design::scale::{scale, set_scale};
use nonos_toolkit::design::size::TOOLTIP_MAX_W;
use nonos_toolkit::widgets::Tooltip;

use super::bounds::{assert_bounded, assert_bounded_in};
use super::boxes::boxed;
use super::samples::LONG;
use super::serial::{serial, SCALES};

/// The texts the proofs show: short, multi-byte and too long for any tooltip.
pub(crate) const TEXTS: [&str; 3] = ["Copy", "Grüße — 日本語", LONG];

fn variants() -> Vec<(String, Tooltip<'static>)> {
    let mut all = Vec::new();
    for text in TEXTS {
        all.push((format!("{text:?}"), Tooltip::new(text)));
        all.push((format!("{text:?} below"), Tooltip::new(text).below()));
    }
    all
}

#[test]
fn tooltip_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn tooltip_paints_inside_a_box_shorter_than_itself() {
    let _g = serial();
    let short =
        |(w, h): (u32, u32)| [boxed(w, h - 1), boxed(w, h / 2), boxed(w / 3, 2), boxed(1, 1)];
    assert_bounded_in(&variants(), short);
}

#[test]
fn tooltip_is_one_line_and_cut_at_its_widest() {
    let _g = serial();
    for q in SCALES {
        set_scale(q);
        let (cap, h) = (scale().px(TOOLTIP_MAX_W), Tooltip::new("Copy").size().1);
        for text in TEXTS {
            let (w, th) = Tooltip::new(text).size();
            assert!(w <= cap && th == h, "{text:?} at {q}/4: {w} by {th}");
        }
        assert_eq!(Tooltip::new(LONG).size().0, cap, "at {q}/4");
        assert!(Tooltip::new("Copy").size().0 < cap, "at {q}/4");
    }
    set_scale(SCALES[0]);
}
