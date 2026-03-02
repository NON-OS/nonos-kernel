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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::sys::{timer, clock};
use crate::shell::commands::utils::format_decimal;

pub fn cmd_uptime() {
    print_line(b"System Uptime:", COLOR_TEXT_WHITE);

    if timer::is_init() {
        let mut uptime_buf = [0u8; 8];
        timer::format_uptime(&mut uptime_buf);

        let mut line = [0u8; 32];
        line[..10].copy_from_slice(b"  Uptime: ");
        line[10..18].copy_from_slice(&uptime_buf);
        print_line(&line[..18], COLOR_GREEN);

        let secs = timer::uptime_seconds();
        let mut sec_line = [0u8; 48];
        sec_line[..12].copy_from_slice(b"  (");
        let len = format_decimal(&mut sec_line[12..], secs);
        sec_line[12+len..12+len+9].copy_from_slice(b" seconds)");
        print_line(&sec_line[..12+len+9], COLOR_TEXT_DIM);
    } else {
        print_line(b"  Timer not initialized", COLOR_YELLOW);
    }
}

pub fn cmd_date() {
    print_line(b"System Time:", COLOR_TEXT_WHITE);

    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);

    let mut line = [0u8; 32];
    line[..8].copy_from_slice(b"  Time: ");
    line[8..16].copy_from_slice(&time_buf);
    line[16..22].copy_from_slice(b" (UTC)");
    print_line(&line[..22], COLOR_GREEN);

    let unix_ms = clock::unix_ms();
    if unix_ms > 0 {
        let mut ts_line = [0u8; 48];
        ts_line[..9].copy_from_slice(b"  Epoch: ");
        let len = format_decimal(&mut ts_line[9..], unix_ms / 1000);
        print_line(&ts_line[..9+len], COLOR_TEXT_DIM);
    }
}
