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

pub struct Sha3_256 {
    keccak: Keccak,
}

impl Sha3_256 {
    pub fn new() -> Self {
        Self {
            keccak: Keccak::new(512, 32, 0x06),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let result = self.keccak.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data)
}
