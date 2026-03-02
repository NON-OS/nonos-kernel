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
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_YELLOW, COLOR_ACCENT};
use crate::shell::commands::utils::trim_bytes;

pub fn cmd_traceroute(cmd: &[u8]) {
    let target = if cmd.len() > 11 {
        trim_bytes(&cmd[11..])
    } else {
        print_line(b"Usage: traceroute <host>", COLOR_TEXT_DIM);
        return;
    };

    if target.is_empty() {
        print_line(b"Usage: traceroute <host>", COLOR_TEXT_DIM);
        return;
    }

    print_line(b"traceroute: Disabled for privacy", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);
    print_line(b"Tor hides your network path", COLOR_ACCENT);
    print_line(b"Use 'tor circuit' to view Tor hops", COLOR_TEXT_DIM);
}
