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

//! Little-endian writer that mirrors `Reader`. Writes append to a
//! `Vec<u8>`; the index encoder uses one writer for the signed
//! prefix and a second short write for the trailing signature so
//! the signer can sign the exact byte range the verifier checks.

extern crate alloc;

use alloc::vec::Vec;

pub(super) struct Writer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    #[cfg(feature = "canonical-encode")]
    pub fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    #[cfg(feature = "canonical-encode")]
    pub fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    #[cfg(feature = "canonical-encode")]
    pub fn u128(&mut self, value: u128) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    pub fn fixed(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    pub fn lp_string(&mut self, value: &str) {
        self.lp_bytes(value.as_bytes());
    }

    pub fn lp_bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.out.extend_from_slice(value);
    }
}
