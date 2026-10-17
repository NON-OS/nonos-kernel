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

//! Dialog: the scrim covers the whole of `at`. Every pixel of `at` outside
//! the panel becomes the `scrim` role blended over what was there, and
//! changes, while no pixel outside `at` changes. The panel is the dialog's
//! size centred in `at`, cut to `at` when the box is smaller.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::rect::centre;
use nonos_toolkit::widgets::{draw, Dialog, Rect};

use super::boxes::{boxed, boxes, inside};
use super::canvas::Canvas;
use super::dialog::dialogs;
use super::serial::{serial, SCALES};

/// The ground the dialog is drawn over.
const GROUND: u32 = 0xFF12_3456;

/// A line for a panel not centred in `at`, or the first pixel off the
/// panel that is not the scrim over the ground, or the first changed
/// pixel outside `at`.
fn uncovered(d: Dialog, at: Rect) -> Option<String> {
    let (p, (w, h)) = (d.panel(at), d.size());
    if p != centre(at, w, h) {
        return Some(format!("panel {p:?} is not {w} by {h} centred"));
    }
    let drawn = Canvas::new(at, GROUND).painted(|fb| d.draw(fb, at));
    let scrim = Canvas::new(at, GROUND).painted(|fb| draw::blend(fb, at, roles().scrim));
    let off = scrim.changed(GROUND).into_iter().filter(|&pt| !inside(p, pt));
    let mut wrong = off.filter(|&(x, y)| drawn.get(x, y) != scrim.get(x, y));
    let outside = drawn.changed(GROUND).into_iter().find(|&pt| !inside(at, pt));
    let covered = scrim.changed(GROUND).len() == (at.w * at.h) as usize;
    let first = wrong.next().map(|pt| format!("{pt:?} off the panel is not the scrim"));
    let first = first.or(outside.map(|pt| format!("{pt:?} outside the box changed")));
    first.or((!covered).then(|| "the scrim leaves some of the box unchanged".to_string()))
}

#[test]
fn dialog_scrim_covers_its_box_round_a_centred_panel() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (name, d) in dialogs() {
            let (w, h) = d.size();
            for at in boxes((w, h)).into_iter().chain([boxed(w / 2, h / 2)]) {
                fails.extend(uncovered(d, at).map(|e| format!("{name} at {q}/4 in {at:?}: {e}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
