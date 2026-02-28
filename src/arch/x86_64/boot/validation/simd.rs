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

use crate::arch::x86_64::cpu;

pub fn get_simd_support() -> SimdSupport {
    let features = cpu::features();

    SimdSupport {
        sse: features.sse,
        sse2: features.sse2,
        sse3: features.sse3,
        ssse3: features.ssse3,
        sse4_1: features.sse4_1,
        sse4_2: features.sse4_2,
        avx: features.avx,
        avx2: features.avx2,
        avx512f: features.avx512f,
        fma: features.fma,
    }
}

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
