// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::utf16::Utf16Buffer;

pub fn utf8_to_utf16(src: &str, dst: &mut [u16]) -> usize {
    let mut idx = 0;
    for c in src.chars() {
        if idx >= dst.len() - 1 {
            break;
        }

        let code = c as u32;
        if code <= 0xFFFF {
            dst[idx] = code as u16;
            idx += 1;
        } else if idx + 1 < dst.len() - 1 {
            let code = code - 0x10000;
            dst[idx] = ((code >> 10) as u16) + 0xD800;
            dst[idx + 1] = ((code & 0x3FF) as u16) + 0xDC00;
            idx += 2;
        } else {
            break;
        }
    }
    dst[idx] = 0;
    idx + 1
}

pub fn format_log_line(buf: &mut Utf16Buffer, level: &str, category: &str, message: &str) {
    buf.clear();
    buf.push_char('[');
    buf.push_str(level);
    buf.push_str("] ");
    buf.push_str(category);
    buf.push_str(": ");
    buf.push_str(message);
    buf.push_str("\r\n");
}

pub fn format_log_line_with_tick(
    buf: &mut Utf16Buffer,
    tick: u64,
    level: &str,
    category: &str,
    message: &str,
) {
    buf.clear();
    buf.push_char('[');

    let mut tick_buf = [0u8; 12];
    let mut n = tick;
    let mut i = tick_buf.len();
    loop {
        i -= 1;
        tick_buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 || i == 0 {
            break;
        }
    }
    for &b in &tick_buf[i..] {
        buf.push_char(b as char);
    }

    buf.push_str("] [");
    buf.push_str(level);
    buf.push_str("] ");
    buf.push_str(category);
    buf.push_str(": ");
    buf.push_str(message);
    buf.push_str("\r\n");
}
