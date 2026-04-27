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

use super::error_struct::InputError;

const LOG_BUFFER_SIZE: usize = 256;

struct LogBuffer {
    data: [u8; LOG_BUFFER_SIZE],
    pos: usize,
}

impl LogBuffer {
    const fn new() -> Self {
        Self { data: [0u8; LOG_BUFFER_SIZE], pos: 0 }
    }
    fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.data[..self.pos]) }
    }
}

impl core::fmt::Write for LogBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = LOG_BUFFER_SIZE - self.pos;
        let to_write = bytes.len().min(remaining);
        if to_write > 0 {
            self.data[self.pos..self.pos + to_write].copy_from_slice(&bytes[..to_write]);
            self.pos += to_write;
        }
        Ok(())
    }
}

pub fn log_error(error: &InputError) {
    use core::fmt::Write;
    let mut buf = LogBuffer::new();
    let _ = write!(buf, "[INPUT ERR] {}", error.code().as_str());
    if let Some(ctx) = error.context() {
        let _ = write!(buf, ": {}", ctx);
    }
    let _ = write!(buf, " @{}\n", error.timestamp());
    crate::arch::x86_64::serial::write_str(buf.as_str());
}
