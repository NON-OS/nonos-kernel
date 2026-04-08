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

pub use super::simd_level::SimdLevel;
pub use super::simd_types::SimdSupport;
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
