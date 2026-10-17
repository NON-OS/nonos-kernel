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

//! Dialog: three buttons, a Danger one among them, stay in the box in every
//! combination of focus, hover and press, at every scale, each combination
//! in one of the four boxes in turn.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::Dialog;

use super::bounds::strays;
use super::boxes::boxes;
use super::dialog::{BODIES, THREE};
use super::serial::{serial, SCALES};

/// No button, or one of the three.
const LIT: [Option<usize>; 4] = [None, Some(0), Some(1), Some(2)];

/// Every combination of a focused, a hovered and a held button.
fn combos() -> impl Iterator<Item = (Option<usize>, Option<usize>, Option<usize>)> {
    LIT.into_iter().flat_map(|f| LIT.into_iter().flat_map(move |h| LIT.map(|p| (f, h, p))))
}

#[test]
fn dialog_paints_inside_its_box_however_its_buttons_are_lit() {
    let _g = serial();
    let mut fails = Vec::new();
    for (c, (f, h, p)) in combos().enumerate() {
        let d = Dialog::new("Delete?").body(BODIES[1]).buttons(THREE).hovered(h).pressed(p);
        let d = f.map_or(d, |f| d.focus(f));
        for q in SCALES {
            set_scale(q);
            let what = format!("focus {f:?} hover {h:?} press {p:?} at {q}/4");
            fails.extend(strays(&what, d, boxes(d.size())[c % 4]));
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
