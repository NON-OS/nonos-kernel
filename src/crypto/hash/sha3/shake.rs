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

extern crate alloc;
use alloc::vec::Vec;

use super::keccak::Keccak;

pub struct Shake128 {
    keccak: Keccak,
}

impl Shake128 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(256, 0, 0x1f),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.keccak.output_len = output_len;
        self.keccak.finalize()
    }

    pub fn digest(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize(output_len)
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Shake256 {
    keccak: Keccak,
}

impl Shake256 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(512, 0, 0x1f),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    pub fn finalize(mut self, output_len: usize) -> Vec<u8> {
        self.keccak.output_len = output_len;
        self.keccak.finalize()
    }

    pub fn digest(data: &[u8], output_len: usize) -> Vec<u8> {
        let mut shake = Self::new();
        shake.update(data);
        shake.finalize(output_len)
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
    Shake128::digest(data, output_len)
}

pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    Shake256::digest(data, output_len)
}
