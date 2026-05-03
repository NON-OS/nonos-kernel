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

/* shows active user sessions - single user in zerostate mode */

use crate::display::framebuffer::{COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::shell::output::print_line;

pub fn cmd_sessions() {
    print_line(b"Active Sessions:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"SESSION   USER        TTY     FROM", COLOR_TEXT_DIM);
    print_line(b"1         anonymous   tty0    local", COLOR_GREEN);

    print_line(b"", COLOR_TEXT_DIM);
    print_line(b"Total: 1 active session", COLOR_TEXT_DIM);
    print_line(b"(Single-user ZeroState mode)", COLOR_YELLOW);
}
