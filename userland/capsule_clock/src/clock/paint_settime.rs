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
use nonos_toolkit::widgets::{Button, Kind, Rect};

use crate::clock::fmt;
use crate::clock::says::DONE;
use crate::clock::state::State;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let buf = fmt::hm(state.edit_hour, state.edit_min);
    let r = roles();
    fb.text_scaled(96, 100, &buf, r.text.argb(), 6);
    adj(fb, 40, "H-");
    adj(fb, 118, "H+");
    adj(fb, 202, "M-");
    adj(fb, 280, "M+");
    Button::new("Apply").kind(Kind::Primary).draw(fb, Rect { x: 40, y: 300, w: 280, h: 48 });
    let ink = if state.set_note == DONE { r.text } else { r.danger };
    fb.text(40, 366, state.set_note, ink.argb());
}

fn adj(fb: &mut PaintBuffer, x: u32, label: &str) {
    Button::new(label).draw(fb, Rect { x, y: 210, w: 68, h: 48 });
}
