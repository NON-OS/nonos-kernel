// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub mod constants;
pub mod error;
pub mod event;
pub mod interface;
pub mod io;
pub mod ring;
pub mod scancode;
#[cfg(test)]
mod tests;
pub use constants::{
    CHAR_RING_SIZE, EVT_RING_SIZE, KBD_DATA, KBD_STATUS, KBD_VECTOR, LED_CAPS_LOCK, LED_NUM_LOCK,
    LED_SCROLL_LOCK, NORMAL, SC_BREAK_BIT, SC_CAPSLOCK, SC_EXT_E0, SC_LALT, SC_LCTRL, SC_LSHIFT,
    SC_RSHIFT, SHIFTED,
};
pub use event::KeyEvent;
pub use interface::{get_keyboard, handle_keyboard_interrupt, init_keyboard, KeyboardInterface};
pub use io::{flush_output_buffer, i8042_init_best_effort, update_leds};
pub use ring::{SpscEvtRing, SpscU8Ring};
pub use scancode::{
    get_modifiers, has_data, has_event, is_alt_pressed, is_caps_lock_active, is_ctrl_pressed,
    is_shift_pressed, pending_char_count, process_scancode, read_char, read_event,
};
