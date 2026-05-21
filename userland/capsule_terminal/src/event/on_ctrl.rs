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

use nonos_app_skeleton::EventOutcome;

use crate::term::state::State;

const CTRL_A: u32 = 0x41;
const CTRL_C: u32 = 0x43;
const CTRL_E: u32 = 0x45;
const CTRL_L: u32 = 0x4C;
const CTRL_U: u32 = 0x55;
const CTRL_A_LO: u32 = 0x61;
const CTRL_C_LO: u32 = 0x63;
const CTRL_E_LO: u32 = 0x65;
const CTRL_L_LO: u32 = 0x6C;
const CTRL_U_LO: u32 = 0x75;

pub fn on_ctrl(state: &mut State, code: u32) -> Option<EventOutcome> {
    match code {
        CTRL_L | CTRL_L_LO => {
            state.scrollback.clear();
            state.scrollback.jump_bottom();
            Some(EventOutcome::Repaint)
        }
        CTRL_C | CTRL_C_LO => {
            state.line.clear();
            state.history.reset_cursor();
            state.scrollback.push_line(b"^C");
            state.scrollback.jump_bottom();
            Some(EventOutcome::Repaint)
        }
        CTRL_U | CTRL_U_LO => {
            state.line.clear();
            Some(EventOutcome::Repaint)
        }
        CTRL_A | CTRL_A_LO => {
            state.line.move_home();
            Some(EventOutcome::Repaint)
        }
        CTRL_E | CTRL_E_LO => {
            state.line.move_end();
            Some(EventOutcome::Repaint)
        }
        _ => None,
    }
}
