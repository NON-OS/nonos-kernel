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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_ACCENT};
use super::constants::{TERM_BUFFER_SIZE, MAX_INPUT_LEN};
use super::state::*;
use super::buffer::print_line;
use super::input::print_prompt;

pub fn init() {
    // SAFETY: Single-threaded terminal initialization
    unsafe {
        for i in 0..TERM_BUFFER_SIZE {
            TERM_BUFFER[i] = b' ';
            TERM_COLORS[i] = COLOR_TEXT_WHITE;
        }
        INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
        CWD[0] = b'/';
        CWD_LEN.store(1, Ordering::Relaxed);
    }
    TERM_CURSOR_X.store(0, Ordering::Relaxed);
    TERM_CURSOR_Y.store(0, Ordering::Relaxed);
    INPUT_LEN.store(0, Ordering::Relaxed);
    INPUT_CURSOR.store(0, Ordering::Relaxed);

    print_line(b"NONOS Terminal v0.8.0", COLOR_ACCENT);
    print_line(b"Type 'help' for available commands.", 0xFF7D8590);
    print_prompt();
}
