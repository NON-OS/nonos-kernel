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
use super::constants::MAX_INPUT_LEN;
use super::state::*;
use super::buffer::*;
use super::commands::execute_command;

const COLOR_CYAN: u32 = 0xFF00D4FF;
const COLOR_GREEN: u32 = 0xFF00FF41;
const COLOR_WHITE: u32 = 0xFFE6E6E6;
const COLOR_DIM: u32 = 0xFF5C6370;

/*
 * hacker-style prompt: anonymous@nønos:~$
 * cyan user, green host, white path, cyan $
 */
pub fn print_prompt() {
    /* user part */
    for &ch in b"anonymous" {
        put_char(ch, COLOR_GREEN);
    }
    put_char(b'@', COLOR_DIM);

    /* host part with special ø character */
    put_char(b'n', COLOR_CYAN);
    put_char(0xD8, COLOR_CYAN);
    for &ch in b"nos" {
        put_char(ch, COLOR_CYAN);
    }
    put_char(b':', COLOR_DIM);

    /* cwd part */
    let cwd_len = CWD_LEN.load(Ordering::Relaxed);
    unsafe {
        for i in 0..cwd_len {
            put_char(CWD[i], COLOR_WHITE);
        }
    }

    /* prompt symbol */
    put_char(b'$', COLOR_GREEN);
    put_char(b' ', COLOR_WHITE);
}

pub fn terminal_key(ch: u8) {
    match ch {
        0x08 | 0x7F => {
            let pos = INPUT_CURSOR.load(Ordering::Relaxed);
            if pos > 0 {
                let len = INPUT_LEN.load(Ordering::Relaxed);
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
                unsafe {
                    execute_command(&INPUT_BUFFER[..len]);
                }
            }
            INPUT_LEN.store(0, Ordering::Relaxed);
            INPUT_CURSOR.store(0, Ordering::Relaxed);
            unsafe {
                INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
            }
            print_prompt();
        }
        0x1B => {
            INPUT_LEN.store(0, Ordering::Relaxed);
            INPUT_CURSOR.store(0, Ordering::Relaxed);
            unsafe {
                INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
            }
        }
        _ if ch >= 0x20 && ch < 0x7F => {
            let len = INPUT_LEN.load(Ordering::Relaxed);
            let pos = INPUT_CURSOR.load(Ordering::Relaxed);

            if len < MAX_INPUT_LEN - 1 {
                unsafe {
                    for i in (pos..len).rev() {
                        INPUT_BUFFER[i + 1] = INPUT_BUFFER[i];
                    }
                    INPUT_BUFFER[pos] = ch;
                }
                INPUT_LEN.store(len + 1, Ordering::Relaxed);
                INPUT_CURSOR.store(pos + 1, Ordering::Relaxed);
                put_char(ch, COLOR_WHITE);
            }
        }
        _ => {}
    }
}
