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

//! Runs the hit proof for a widget over its variants, states, scales and
//! boxes.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Rect;

use super::hits::disagree;
use super::serial::SCALES;
use super::states::looks;
use super::widget::Widget;

/// Asserts `hit` takes the pixels each variant draws, in every look, scale
/// and box `place` gives for its size, and no point outside the box.
pub(crate) fn assert_agree<W: Widget, const N: usize>(
    variants: &[(String, W)],
    place: impl Fn((u32, u32)) -> [Rect; N],
    hit: impl Fn(&W, Rect, i32, i32) -> bool,
) {
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, w) in variants {
            for st in looks() {
                let w = w.with(st);
                for at in place(w.pref()) {
                    let what = format!("{name} {st:?} at {q}/4");
                    fails.extend(disagree(&what, w, at, |x, y| hit(&w, at, x, y)));
                }
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
