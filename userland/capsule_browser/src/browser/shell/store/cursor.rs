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

use super::put::cap;

/// Reads a record front to back. Every read past the end is `None`.
pub struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, at: 0 }
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.buf.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn i64(&mut self) -> Option<i64> {
        let mut le = [0u8; 8];
        le.copy_from_slice(self.bytes(8)?);
        Some(i64::from_le_bytes(le))
    }

    /// A `u16`-length string: `None` on a short read, `Some(None)` when it is
    /// not UTF-8. One longer than `MAX_STR` is cut to it on a char boundary.
    pub fn str(&mut self) -> Option<Option<String>> {
        let n = self.u16()? as usize;
        let raw = self.bytes(n)?;
        Some(core::str::from_utf8(raw).ok().map(|s| String::from(cap(s))))
    }
}
