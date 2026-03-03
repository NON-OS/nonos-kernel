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

use crate::network::onion::OnionError;

pub(super) struct DerParser<'a> {
    pub(super) data: &'a [u8],
    pub(super) offset: usize,
}

impl<'a> DerParser<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub(super) fn expect_tag(&mut self, expected: u8) -> Result<(), OnionError> {
        if self.offset >= self.data.len() {
            return Err(OnionError::CryptoError);
        }
        let tag = self.data[self.offset];
        if tag != expected {
            return Err(OnionError::CryptoError);
        }
        self.offset += 1;
        Ok(())
    }

    pub(super) fn expect_sequence(&mut self) -> Result<(), OnionError> {
        self.expect_tag(0x30)
    }

    pub(super) fn read_length(&mut self) -> Result<usize, OnionError> {
        if self.offset >= self.data.len() {
            return Err(OnionError::CryptoError);
        }

        let first_byte = self.data[self.offset];
        self.offset += 1;

        if first_byte & 0x80 == 0 {
            Ok(first_byte as usize)
        } else {
            let length_bytes = (first_byte & 0x7F) as usize;
            if length_bytes == 0 || length_bytes > 4 {
                return Err(OnionError::CryptoError);
            }

            if self.offset + length_bytes > self.data.len() {
                return Err(OnionError::CryptoError);
            }

            let mut length = 0usize;
            for _ in 0..length_bytes {
                length = (length << 8) | self.data[self.offset] as usize;
                self.offset += 1;
            }
            Ok(length)
        }
    }

    pub(super) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], OnionError> {
        if self.offset + count > self.data.len() {
            return Err(OnionError::CryptoError);
        }
        let result = &self.data[self.offset..self.offset + count];
        self.offset += count;
        Ok(result)
    }

    pub(super) fn skip(&mut self, count: usize) -> Result<(), OnionError> {
        if self.offset + count > self.data.len() {
            return Err(OnionError::CryptoError);
        }
        self.offset += count;
        Ok(())
    }

    pub(super) fn skip_structure(&mut self) -> Result<(), OnionError> {
        self.offset += 1;
        let length = self.read_length()?;
        self.skip(length)
    }

    pub(super) fn peek_tag(&self) -> Option<u8> {
        if self.offset < self.data.len() {
            Some(self.data[self.offset])
        } else {
            None
        }
    }

    pub(super) fn has_more(&self) -> bool {
        self.offset < self.data.len()
    }

    pub(super) fn read_remaining(&mut self) -> Result<&'a [u8], OnionError> {
        let result = &self.data[self.offset..];
        self.offset = self.data.len();
        Ok(result)
    }
}
