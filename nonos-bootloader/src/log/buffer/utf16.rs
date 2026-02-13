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

pub const UTF16_BUFFER_SIZE: usize = 512;
/// UTF-16 buffer for UEFI output
pub struct Utf16Buffer {
    data: [u16; UTF16_BUFFER_SIZE],
    len: usize,
}

impl Utf16Buffer {
    /// Create a new empty buffer
    pub const fn new() -> Self {
        Self {
            data: [0u16; UTF16_BUFFER_SIZE],
            len: 0,
        }
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.len = 0;
        self.data[0] = 0;
    }

    /// Append a character
    pub fn push_char(&mut self, c: char) -> bool {
        if self.len >= UTF16_BUFFER_SIZE - 1 {
            return false;
        }

        let code = c as u32;
        if code <= 0xFFFF {
            self.data[self.len] = code as u16;
            self.len += 1;
        } else if self.len + 1 < UTF16_BUFFER_SIZE - 1 {
            // Surrogate pair for characters outside BMP
            let code = code - 0x10000;
            self.data[self.len] = ((code >> 10) as u16) + 0xD800;
            self.data[self.len + 1] = ((code & 0x3FF) as u16) + 0xDC00;
            self.len += 2;
        } else {
            return false;
        }

        self.data[self.len] = 0; // Null terminate
        true
    }

    /// Append a string
    pub fn push_str(&mut self, s: &str) -> usize {
        let mut count = 0;
        for c in s.chars() {
            if !self.push_char(c) {
                break;
            }
            count += 1;
        }
        count
    }

    /// Get the buffer as a slice including null terminator
    pub fn as_slice(&self) -> &[u16] {
        &self.data[..=self.len]
    }

    pub fn as_cstr16(&self) -> Option<&uefi::CStr16> {
        uefi::CStr16::from_u16_with_nul(&self.data[..=self.len]).ok()
    }

    /// Get current length (not including null terminator)
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn remaining(&self) -> usize {
        UTF16_BUFFER_SIZE - 1 - self.len
    }
}

impl Default for Utf16Buffer {
    fn default() -> Self {
        Self::new()
    }
}

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
    dst[idx] = 0; // Null terminate
    idx + 1
}

/// Format a log line into UTF-16 buffer
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

/// Format a timestamped log line into UTF-16 buffer
pub fn format_log_line_with_tick(
    buf: &mut Utf16Buffer,
    tick: u64,
    level: &str,
    category: &str,
    message: &str,
) {
    buf.clear();
    buf.push_char('[');
    // Format tick as simple decimal up to 10 digits
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
