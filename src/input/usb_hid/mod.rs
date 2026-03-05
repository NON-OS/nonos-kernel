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

mod pci;
mod xhci;
mod ring;
mod transfer;
mod hid;
mod state;

pub use pci::find_xhci;
pub use xhci::init_xhci;
pub use ring::{queue_cmd, queue_ep0, queue_hid, ring_db, wait_event};
pub use hid::{process_keyboard_report, process_mouse_report, hid_to_ascii, start_hid_poll};
pub use state::{
    set_screen_bounds, is_available, keyboard_available, mouse_available,
    mouse_position, left_pressed, right_pressed, init, poll_keyboard, poll_mouse,
};
