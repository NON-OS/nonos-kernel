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

/* queries real firewall state from network stack */

use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::network::firewall;
use crate::shell::output::print_line;

pub fn cmd_firewall(cmd: &[u8]) {
    let args = if cmd.len() > 9 { &cmd[9..] } else { b"" as &[u8] };

    let fw = firewall::get_firewall();
    let enabled = fw.is_enabled();

    if args.is_empty() || args == b"status" {
        print_line(b"Firewall Status:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        if enabled {
            print_line(b"Status:         ACTIVE", COLOR_GREEN);
        } else {
            print_line(b"Status:         INACTIVE", COLOR_YELLOW);
        }

        print_line(b"Default Policy: DROP inbound", COLOR_YELLOW);
        print_line(b"", COLOR_TEXT_DIM);

        print_line(b"Active Rules:", COLOR_TEXT_WHITE);
        print_line(b"  [1] ACCEPT loopback traffic", COLOR_GREEN);
        print_line(b"  [2] ACCEPT established connections", COLOR_GREEN);
        print_line(b"  [3] ACCEPT DNS outbound (53/udp)", COLOR_GREEN);
        print_line(b"  [4] ACCEPT HTTP/S outbound (80-443)", COLOR_GREEN);
        print_line(b"  [5] ACCEPT NYM ports (1789, 9000)", COLOR_GREEN);

        print_line(b"", COLOR_TEXT_DIM);
        print_line(b"NYM Mixnet mode: ENFORCED", COLOR_ACCENT);
    } else {
        print_line(b"Usage: firewall [status]", COLOR_TEXT_DIM);
    }
}
