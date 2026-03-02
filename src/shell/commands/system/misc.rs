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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_ACCENT};

pub fn cmd_cpu() {
    print_line(b"CPU Information:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Architecture:  x86_64 (AMD64)", COLOR_TEXT);
    print_line(b"Mode:          Long Mode (64-bit)", COLOR_TEXT);
    print_line(b"Ring:          0 (Kernel)", COLOR_TEXT);
    print_line(b"IOPL:          3 (Full I/O)", COLOR_TEXT);
    print_line(b"Features:      SSE, SSE2", COLOR_TEXT);
}

pub fn cmd_clear() {
    crate::shell::terminal::scroll();
}

pub fn cmd_hostname() {
    print_line(b"n\xd8nos-zerostate", COLOR_ACCENT);
}

pub fn cmd_uname() {
    print_line(b"N\xd8NOS 1.0.0 x86_64 N\xd8NOS Kernel", COLOR_TEXT);
}
