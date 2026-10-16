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

//! The bounds proof: whatever a widget draws lands inside the box it is given.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Rect;

use super::boxes::{boxes, inside};
use super::canvas::Canvas;
use super::serial::SCALES;
use super::states::states;
use super::widget::Widget;

/// Two prefills, so a blend that rounds back to one still shows on the other.
const SENTINELS: [u32; 2] = [0xFF12_3456, 0xFFED_CBA9];

/// A line naming `what` when `w` changes any pixel outside `at`.
pub(crate) fn strays<W: Widget>(what: &str, w: W, at: Rect) -> Option<String> {
    for fill in SENTINELS {
        let c = Canvas::new(at, fill).painted(|fb| w.paint(fb, at));
        let out: Vec<_> = c.changed(fill).into_iter().filter(|p| !inside(at, *p)).collect();
        if let Some(first) = out.first() {
            return Some(format!("{what} in {at:?}: {} outside, first {first:?}", out.len()));
        }
    }
    None
}

/// `assert_bounded_in` over the boxes `boxes` gives for the widget's size.
pub(crate) fn assert_bounded<W: Widget>(variants: &[(String, W)]) {
    assert_bounded_in(variants, boxes);
}

/// Draws every variant in every state, at every scale, in every box `place`
/// gives for its size, and asserts nothing lands outside the box.
pub(crate) fn assert_bounded_in<W: Widget, const N: usize>(
    variants: &[(String, W)],
    place: impl Fn((u32, u32)) -> [Rect; N],
) {
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, w) in variants {
            for st in states() {
                let w = w.with(st);
                for at in place(w.pref()) {
                    fails.extend(strays(&format!("{name} {st:?} at {q}/4"), w, at));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
