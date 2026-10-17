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
use crate::clock::state::State;
use crate::clock::tabs::Tab;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let e = state.sw.elapsed(state.now_ms);
    let buf = fmt::ms_clock(e);
    fb.text_scaled(40, 150, &buf, roles().text.argb(), 5);
    let label = if state.sw.running { "Stop" } else { "Start" };
    let k = keys(Tab::Stopwatch);
    Button::new(label).kind(Kind::Primary).state(look(state, Target::Key(0))).draw(fb, k[0]);
    Button::new("Reset").state(look(state, Target::Key(1))).draw(fb, k[1]);
}
