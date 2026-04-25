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

mod api;
pub mod controller;
pub mod controller_constants;
pub mod controller_init;
pub mod controller_io;
mod controller_struct;
pub mod globals;
mod interrupt;
pub mod keyboard;
pub mod mouse;
pub mod mouse_commands;
pub mod mouse_init;
pub mod mouse_parse;
mod mouse_state;
mod mouse_types;
mod stats;

pub use super::error::{Ps2Error, Ps2Result};
pub use api::{has_keyboard, has_mouse, init, is_initialized, set_leds, set_typematic};
pub use controller::Controller;
pub use controller_constants::*;
pub use controller_init::init_controller;
pub use controller_io::{
    has_data, is_mouse_data, read_data, read_data_nowait, wait_input, wait_output, write_data,
    write_port2,
};
pub use globals::{CONTROLLER, DECODER, INITIALIZED, KEYBOARD, MOUSE};
pub use interrupt::handle_interrupt;
pub use keyboard::{Keyboard, ScanCodeDecoder, ScanCodeSet, ScanCodeState, TypematicConfig};
pub use mouse::{Mouse, MousePacket, MouseType, Resolution};
pub use mouse_commands::*;
pub use mouse_init::init_mouse;
pub use mouse_parse::parse_packet;
pub use stats::{get_stats, Ps2Stats};
