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

use super::buffer::print_line;
use super::constants::{MAX_INPUT_LEN, TERM_BUFFER_SIZE};
use super::input::print_prompt;
use super::state::*;
use core::sync::atomic::Ordering;

const COLOR_TEAL: u32 = 0xFF66FFFF;
const COLOR_GREEN: u32 = 0xFF00E676;
const COLOR_DIM: u32 = 0xFF5C6370;
const _COLOR_YELLOW: u32 = 0xFFFFD740;
const COLOR_WHITE: u32 = 0xFFF0F6FC;

pub fn init() {
    unsafe {
        for i in 0..TERM_BUFFER_SIZE {
            TERM_BUFFER[i] = b' ';
            TERM_COLORS[i] = COLOR_WHITE;
        }
        INPUT_BUFFER = [0u8; MAX_INPUT_LEN];
        CWD[0] = b'~';
        CWD_LEN.store(1, Ordering::Relaxed);
    }
    TERM_CURSOR_X.store(0, Ordering::Relaxed);
    TERM_CURSOR_Y.store(0, Ordering::Relaxed);
    INPUT_LEN.store(0, Ordering::Relaxed);
    INPUT_CURSOR.store(0, Ordering::Relaxed);

    print_line(b"", COLOR_DIM);
    print_line(b" ##    ## ######  ##    ## ######  ######", COLOR_TEAL);
    print_line(b" ###   ## ##   ## ###   ## ##   ## ##    ", COLOR_TEAL);
    print_line(b" ## #  ## ##   ## ## #  ## ##   ## ##### ", COLOR_TEAL);
    print_line(b" ##  # ## ##   ## ##  # ## ##   ##     ##", COLOR_TEAL);
    print_line(b" ##   ### ##   ## ##   ### ##   ## ##  ##", COLOR_TEAL);
    print_line(b" ##    ## ######  ##    ## ######  ##### ", COLOR_TEAL);
    print_line(b"", COLOR_DIM);
    print_line(b" ZeroState Terminal", COLOR_GREEN);
    print_line(b"", COLOR_DIM);
    print_line(b" Type 'help' for commands", COLOR_DIM);
    print_line(b"", COLOR_DIM);

    print_prompt();
}
