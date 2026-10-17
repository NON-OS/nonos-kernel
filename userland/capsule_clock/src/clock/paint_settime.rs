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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Button, Kind};

use crate::clock::controls::{keys, Target};
use crate::clock::fmt;
use crate::clock::hover::look;
use crate::clock::says::DONE;
use crate::clock::state::State;
use crate::clock::tabs::Tab;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let buf = fmt::hm(state.edit_hour, state.edit_min);
    let r = roles();
    fb.text_scaled(96, 100, &buf, r.text.argb(), 6);
    let k = keys(Tab::Set);
    for (i, name) in ["H-", "H+", "M-", "M+", "Apply"].into_iter().enumerate() {
        let kind = if i == 4 { Kind::Primary } else { Kind::Secondary };
        Button::new(name).kind(kind).state(look(state, Target::Key(i))).draw(fb, k[i]);
    }
    let ink = if state.set_note == DONE { r.text } else { r.danger };
    fb.text(40, 366, state.set_note, ink.argb());
}
