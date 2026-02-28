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

use super::simd::{SimdLevel, SimdSupport};

#[test]
fn test_simd_level_ordering() {
    assert!(SimdLevel::Avx512 > SimdLevel::Avx2);
    assert!(SimdLevel::Avx2 > SimdLevel::Avx);
    assert!(SimdLevel::Sse2 > SimdLevel::Sse);
}

#[test]
fn test_register_width() {
    assert_eq!(SimdLevel::Sse.register_width(), 128);
    assert_eq!(SimdLevel::Avx.register_width(), 256);
    assert_eq!(SimdLevel::Avx512.register_width(), 512);
}

#[test]
fn test_simd_support_highest_level() {
    let support = SimdSupport {
        sse: true,
        sse2: true,
        avx: true,
        ..Default::default()
    };
    assert_eq!(support.highest_level(), SimdLevel::Avx);
}
