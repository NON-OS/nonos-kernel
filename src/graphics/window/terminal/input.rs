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
use crate::graphics::framebuffer::COLOR_TEXT_WHITE;
use super::constants::MAX_INPUT_LEN;
use super::state::*;
use super::buffer::*;
use super::commands::execute_command;

pub fn print_prompt() {
    let cwd_len = CWD_LEN.load(Ordering::Relaxed);
    // SAFETY: Read-only access to CWD
    unsafe {
        for i in 0..cwd_len {
            put_char(CWD[i], crate::graphics::framebuffer::COLOR_ACCENT);
        }
    }
    put_char(b'>', crate::graphics::framebuffer::COLOR_ACCENT);
    put_char(b' ', COLOR_TEXT_WHITE);
}

pub fn terminal_key(ch: u8) {
    match ch {
        0x08 | 0x7F => {
            let pos = INPUT_CURSOR.load(Ordering::Relaxed);
            if pos > 0 {
                let len = INPUT_LEN.load(Ordering::Relaxed);
                // SAFETY: Single-threaded input buffer access
                unsafe {
                    for i in pos - 1..len - 1 {
                        INPUT_BUFFER[i] = INPUT_BUFFER[i + 1];
                    }
                    INPUT_BUFFER[len - 1] = 0;
                }
                INPUT_LEN.store(len - 1, Ordering::Relaxed);
                INPUT_CURSOR.store(pos - 1, Ordering::Relaxed);
            }
        }
        0x0D | 0x0A => {
            newline();
            let len = INPUT_LEN.load(Ordering::Relaxed);
            if len > 0 {
                // SAFETY: Single-threaded input buffer access
                unsafe {
                    execute_command(&INPUT_BUFFER[..len]);
                }
            }
            INPUT_LEN.store(0, Ordering::Relaxed);
            INPUT_CURSOR.store(0, Ordering::Relaxed);
            // SAFETY: Single-threaded input buffer access
            unsafe {
                INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
            }
            print_prompt();
        }
        0x1B => {
            INPUT_LEN.store(0, Ordering::Relaxed);
            INPUT_CURSOR.store(0, Ordering::Relaxed);
            // SAFETY: Single-threaded input buffer access
            unsafe {
                INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
            }
        }
        _ if ch >= 0x20 && ch < 0x7F => {
            let len = INPUT_LEN.load(Ordering::Relaxed);
            let pos = INPUT_CURSOR.load(Ordering::Relaxed);

            if len < MAX_INPUT_LEN - 1 {
                // SAFETY: Bounds checked above
                unsafe {
                    for i in (pos..len).rev() {
                        INPUT_BUFFER[i + 1] = INPUT_BUFFER[i];
                    }
                    INPUT_BUFFER[pos] = ch;
                }
                INPUT_LEN.store(len + 1, Ordering::Relaxed);
                INPUT_CURSOR.store(pos + 1, Ordering::Relaxed);
                put_char(ch, COLOR_TEXT_WHITE);
            }
        }
        _ => {}
    }
}
