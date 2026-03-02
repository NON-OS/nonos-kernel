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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};

use super::cwd::get_cwd;

pub fn cmd_whoami() {
    print_line(b"anonymous", COLOR_GREEN);
    print_line(b"(N\\xd8NOS single-user mode)", COLOR_TEXT_DIM);
}

pub fn cmd_id() {
    print_line(b"uid=0(anonymous) gid=0(root) groups=0(root)", COLOR_TEXT);
    print_line(b"(Single-user anonymous mode)", COLOR_TEXT_DIM);
}

pub fn cmd_env() {
    print_line(b"Environment Variables:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"USER=anonymous", COLOR_TEXT);

    let mut home_line = [0u8; 80];
    home_line[..5].copy_from_slice(b"HOME=");
    let cwd = get_cwd();
    let cwd_bytes = cwd.as_bytes();
    let cwd_len = cwd_bytes.len().min(60);
    home_line[5..5+cwd_len].copy_from_slice(&cwd_bytes[..cwd_len]);
    print_line(&home_line[..5+cwd_len], COLOR_TEXT);

    print_line(b"SHELL=/bin/nsh", COLOR_TEXT);
    print_line(b"PATH=/bin:/capsules/bin", COLOR_TEXT);
    print_line(b"TERM=nonos-term", COLOR_TEXT);
    print_line(b"LANG=C.UTF-8", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"ANON_MODE=true", COLOR_GREEN);
    print_line(b"ZEROSTATE=enabled", COLOR_GREEN);
    print_line(b"PERSISTENCE=none", COLOR_YELLOW);
}

pub fn cmd_history() {
    print_line(b"Command History:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"(History disabled for privacy)", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"ZeroState Policy:", COLOR_TEXT_WHITE);
    print_line(b"  * No command logging", COLOR_GREEN);
    print_line(b"  * No session persistence", COLOR_GREEN);
    print_line(b"  * All data erased on shutdown", COLOR_GREEN);
}
