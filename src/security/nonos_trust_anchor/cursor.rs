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

use super::error::TrustAnchorDecodeError;

pub(super) struct Cursor<'a> {
    pub(super) buf: &'a [u8],
    pub(super) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], TrustAnchorDecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(TrustAnchorDecodeError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub(super) fn u8(&mut self) -> Result<u8, TrustAnchorDecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16_be(&mut self) -> Result<u16, TrustAnchorDecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub(super) fn u32_be(&mut self) -> Result<u32, TrustAnchorDecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(super) fn u64_be(&mut self) -> Result<u64, TrustAnchorDecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], TrustAnchorDecodeError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
}
