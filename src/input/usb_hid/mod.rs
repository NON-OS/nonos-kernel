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

mod entry;
pub(crate) mod hid;
mod pci;
mod poll;
pub(crate) mod ring;
mod state;
pub(crate) mod transfer;
mod xhci;

pub use entry::init;
pub use hid::{hid_to_ascii, process_keyboard_report, process_mouse_report, start_hid_poll};
pub use pci::find_xhci;
pub use poll::{poll_keyboard, poll_mouse};
pub use ring::{check_event, queue_cmd, queue_ep0, queue_hid, ring_db, wait_event};
pub use state::{is_available, keyboard_available, mouse_available, set_screen_bounds};
pub use state::{left_pressed, mouse_position, right_pressed};
pub(crate) use state::{
    KBD_AVAIL, MOUSE_AVAIL, MOUSE_BTN, MOUSE_X, MOUSE_Y, SCR_H, SCR_W, TABLET_MODE, USB_INIT,
};
pub use xhci::init_xhci;
