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

use alloc::string::String;

pub(super) fn print_line(msg: &[u8]) {
    crate::shell::output::print_line(msg, crate::display::framebuffer::COLOR_WHITE);
}

pub(super) fn print_line_fmt(msg: &[u8]) {
    crate::shell::output::print_line(msg, crate::display::framebuffer::COLOR_WHITE);
}

pub(super) fn format_timestamp(ts: u64) -> String {
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", years, month, day, hours, mins, secs)
}
