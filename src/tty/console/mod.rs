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

mod keyboard;
mod screen;
mod vt;

pub use keyboard::{process_key, set_keymap, KeyEvent};
pub use screen::{clear_screen, scroll_down, scroll_up, ScreenBuffer};
pub use vt::{console_ioctl, get_active_vt, init_vts, switch_vt, VirtualTerminal};

use crate::tty::buffer::TtyBuffer;
use spin::Mutex;

static CONSOLE_BUF: Mutex<TtyBuffer> = Mutex::new(TtyBuffer::new());

pub fn console_read(buf: &mut [u8]) -> Result<usize, i32> {
    let mut console_buf = CONSOLE_BUF.lock();
    let mut count = 0;
    for byte in buf.iter_mut() {
        if let Some(c) = console_buf.pop() {
            *byte = c;
            count += 1;
        } else {
            break;
        }
    }
    if count == 0 {
        return Err(-11);
    }
    Ok(count)
}

pub fn console_write(buf: &[u8]) -> Result<usize, i32> {
    match get_active_vt() {
        Some(vt) => vt.write(buf),
        None => Err(-5),
    }
}

pub fn console_poll() -> u32 {
    let has_data = !CONSOLE_BUF.lock().is_empty();
    if has_data {
        0x01 | 0x04
    } else {
        0x04
    }
}

pub fn console_input(c: u8) {
    CONSOLE_BUF.lock().push(c);
}
