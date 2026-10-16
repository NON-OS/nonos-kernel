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
use crate::clock::state::State;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let e = state.sw.elapsed(state.now_ms);
    let buf = fmt::ms_clock(e);
    fb.text_scaled(40, 150, &buf, roles().text.argb(), 5);
    let label = if state.sw.running { "Stop" } else { "Start" };
    Button::new(label).kind(Kind::Primary).draw(fb, Rect { x: 40, y: 300, w: 130, h: 46 });
    Button::new("Reset").draw(fb, Rect { x: 190, y: 300, w: 130, h: 46 });
}
