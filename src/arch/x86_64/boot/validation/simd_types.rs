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

use super::simd_level::SimdLevel;

#[derive(Debug, Clone, Copy, Default)]
pub struct SimdSupport {
    pub sse: bool,
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub fma: bool,
}

impl SimdSupport {
    pub fn highest_level(&self) -> SimdLevel {
        if self.avx512f {
            SimdLevel::Avx512
        } else if self.avx2 {
            SimdLevel::Avx2
        } else if self.avx {
            SimdLevel::Avx
        } else if self.sse4_2 {
            SimdLevel::Sse42
        } else if self.sse4_1 {
            SimdLevel::Sse41
        } else if self.ssse3 {
            SimdLevel::Ssse3
        } else if self.sse3 {
            SimdLevel::Sse3
        } else if self.sse2 {
            SimdLevel::Sse2
        } else if self.sse {
            SimdLevel::Sse
        } else {
            SimdLevel::None
        }
    }
}
