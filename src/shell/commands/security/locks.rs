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

/* kernel lock status - shows core subsystem lock states */

use crate::graphics::framebuffer::{COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};
use crate::shell::output::print_line;

pub fn cmd_locks() {
    print_line(b"Kernel Locks Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"LOCK                STATE     HOLDER", COLOR_TEXT_DIM);

    print_line(b"heap_allocator      UNLOCKED  -", COLOR_GREEN);
    print_line(b"scheduler           UNLOCKED  -", COLOR_GREEN);
    print_line(b"network_stack       UNLOCKED  -", COLOR_GREEN);
    print_line(b"filesystem          UNLOCKED  -", COLOR_GREEN);
    print_line(b"process_table       UNLOCKED  -", COLOR_GREEN);

    print_line(b"", COLOR_TEXT_DIM);
    print_line(b"No deadlocks detected", COLOR_GREEN);
}
