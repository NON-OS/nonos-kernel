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
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_YELLOW};

pub fn cmd_chown(cmd: &[u8]) {
    let args = if cmd.len() > 6 {
        trim_bytes(&cmd[6..])
    } else {
        print_line(b"Usage: chown <owner> <file>", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"Usage: chown <owner> <file>", COLOR_TEXT_DIM);
        return;
    }

    print_line(b"chown: Single-user system (anonymous)", COLOR_YELLOW);
    print_line(b"All files owned by anonymous user", COLOR_TEXT_DIM);
    print_line(b"N\\xd8NOS runs in ZeroState mode", COLOR_TEXT_DIM);
}
