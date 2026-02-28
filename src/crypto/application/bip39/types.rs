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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    Words12 = 128,
    Words15 = 160,
    Words18 = 192,
    Words21 = 224,
    Words24 = 256,
}

impl MnemonicStrength {
    pub fn word_count(&self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }

    pub fn entropy_bits(&self) -> usize {
        *self as usize
    }

    pub fn checksum_bits(&self) -> usize {
        self.entropy_bits() / 32
    }
}
