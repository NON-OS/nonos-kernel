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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdLevel {
    None = 0,
    Sse = 1,
    Sse2 = 2,
    Sse3 = 3,
    Ssse3 = 4,
    Sse41 = 5,
    Sse42 = 6,
    Avx = 7,
    Avx2 = 8,
    Avx512 = 9,
}

impl SimdLevel {
    pub const fn register_width(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Sse | Self::Sse2 | Self::Sse3 | Self::Ssse3 | Self::Sse41 | Self::Sse42 => 128,
            Self::Avx | Self::Avx2 => 256,
            Self::Avx512 => 512,
        }
    }
}
