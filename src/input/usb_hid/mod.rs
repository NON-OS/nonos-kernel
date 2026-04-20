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
pub(crate) mod ring;
pub(crate) mod transfer;
pub(crate) mod hid;
mod state;
mod poll;
mod entry;

pub(crate) use state::{USB_INIT, KBD_AVAIL, MOUSE_AVAIL, TABLET_MODE, MOUSE_X, MOUSE_Y, MOUSE_BTN, SCR_W, SCR_H};
pub use state::{set_screen_bounds, is_available, keyboard_available, mouse_available};
pub use state::{mouse_position, left_pressed, right_pressed};
pub use poll::{poll_keyboard, poll_mouse};
pub use entry::init;
pub use pci::find_xhci;
pub use xhci::init_xhci;
pub use ring::{queue_cmd, queue_ep0, queue_hid, ring_db, wait_event, check_event};
pub use hid::{process_keyboard_report, process_mouse_report, hid_to_ascii, start_hid_poll};
