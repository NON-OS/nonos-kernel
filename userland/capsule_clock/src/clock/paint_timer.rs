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
use nonos_toolkit::theme::contrast::{at_least, BODY};
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Button, Kind};

use crate::clock::controls::{keys, Target};
use crate::clock::fmt;
use crate::clock::hover::look;
use crate::clock::state::State;
use crate::clock::tabs::Tab;

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let r = roles();
    let (danger, ground) = (r.danger.argb(), r.bg.argb());
    let mut ink = r.text.argb();
    if state.timer.fired {
        fb.fill_rect(0, 60, 360, 380, danger);
        ink = if at_least(ground, danger, BODY) { ground } else { ink };
    }
    let rem = state.timer.remaining(state.now_ms);
    let buf = fmt::ms_ms(rem);
    fb.text_scaled(84, 150, &buf, ink, 6);
    let label = if state.timer.running { "Pause" } else { "Start" };
    let k = keys(Tab::Timer);
    for (i, name) in ["1m", "5m", "10m", label, "Reset"].into_iter().enumerate() {
        let kind = if i == 3 { Kind::Primary } else { Kind::Secondary };
        Button::new(name).kind(kind).state(look(state, Target::Key(i))).draw(fb, k[i]);
    }
}
