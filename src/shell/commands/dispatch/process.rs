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

use crate::shell::commands::processes::*;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_process(cmd: &[u8]) -> bool {
    if cmd == b"monitor" || cmd == b"top" || cmd == b"htop" {
        cmd_top();
    } else if cmd == b"kill" || starts_with(cmd, b"kill ") {
        cmd_kill(cmd);
    } else if cmd == b"pgrep" || starts_with(cmd, b"pgrep ") {
        cmd_pgrep(cmd);
    } else if cmd == b"pkill" || starts_with(cmd, b"pkill ") {
        cmd_pkill(cmd);
    } else if cmd == b"nice" || starts_with(cmd, b"nice ") {
        cmd_nice(cmd);
    } else if cmd == b"renice" || starts_with(cmd, b"renice ") {
        cmd_renice(cmd);
    } else if cmd == b"jobs" {
        cmd_jobs();
    } else if cmd == b"pidof" || starts_with(cmd, b"pidof ") {
        cmd_pidof(cmd);
    } else {
        return false;
    }
    true
}
