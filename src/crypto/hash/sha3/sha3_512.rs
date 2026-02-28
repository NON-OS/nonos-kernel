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

use super::keccak::Keccak;

pub struct Sha3_512 {
    keccak: Keccak,
}

impl Sha3_512 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(1024, 64, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
        let result = self.keccak.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::digest(data)
}
