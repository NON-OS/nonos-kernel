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

pub mod controller;
pub mod keyboard;
pub mod mouse;
mod controller_constants;
mod controller_io;
mod controller_init;
mod controller_struct;
mod mouse_types;
mod mouse_commands;
mod mouse_init;
mod mouse_parse;
mod mouse_state;
mod globals;
mod api;
mod interrupt;
mod stats;

pub use controller::Controller;
pub use keyboard::{Keyboard, ScanCodeDecoder, ScanCodeSet, ScanCodeState, TypematicConfig};
pub use mouse::{Mouse, MousePacket, MouseType, Resolution};
pub use super::error::{Ps2Error, Ps2Result};
pub use api::{init, is_initialized, has_keyboard, has_mouse, set_leds, set_typematic};
pub use interrupt::handle_interrupt;
pub use stats::{Ps2Stats, get_stats};
