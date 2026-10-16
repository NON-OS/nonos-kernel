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

use nonos_toolkit::widgets::Tone;

use super::risk_strip::CLASSES;

// Scheduler state coloured by what it means to the user: running is healthy,
// idle is parked and answers the moment a message arrives, stopped and zombie
// are the two states worth noticing. Idle and an unknown code are plain, which
// draws muted.
pub fn state_tint(state: u8) -> Tone {
    match state {
        1 => Tone::Accent,
        2 => Tone::Ok,
        4 => Tone::Warn,
        5 => Tone::Danger,
        _ => Tone::Plain,
    }
}

// A grant chip takes the tone of the sensitive class it belongs to, so the
// inspector's chip list and the table's risk strip agree at a glance.
pub fn cap_tint(bit: u64) -> Tone {
    CLASSES.iter().find(|(mask, _)| bit & mask != 0).map(|(_, tone)| *tone).unwrap_or(Tone::Plain)
}
