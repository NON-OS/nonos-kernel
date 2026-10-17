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

//! Dialog: every dialog stays in its box at every scale, in boxes its own
//! size, wider and narrower, and in boxes smaller than its panel. Dialog `k`
//! is drawn in every eighth of the 32 states from state `k`, so every state
//! is drawn at every scale in every box, with some button indices past the
//! last.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Rect;

use super::bounds::strays;
use super::boxes::{boxed, boxes};
use super::dialog::dialogs;
use super::serial::{serial, SCALES};
use super::states::states;

/// Asserts each dialog, in its share of the states `share` apart, paints
/// nothing outside any box `place` gives for its size, at every scale.
fn assert_inside<const N: usize>(share: usize, place: impl Fn((u32, u32)) -> [Rect; N]) {
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (k, (name, d)) in dialogs().into_iter().enumerate() {
            for st in states().skip(k % share).step_by(share) {
                for at in place(d.size()) {
                    fails.extend(strays(&format!("{name} {st:?} at {q}/4"), d.state(st), at));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn dialog_paints_inside_its_box() {
    let _g = serial();
    assert_inside(8, boxes);
}

#[test]
fn dialog_paints_inside_a_box_smaller_than_its_panel() {
    let _g = serial();
    let small =
        |(w, h): (u32, u32)| [boxed(w - 1, h - 1), boxed(w, h / 2), boxed(w / 3, 2), boxed(1, 1)];
    assert_inside(16, small);
}
