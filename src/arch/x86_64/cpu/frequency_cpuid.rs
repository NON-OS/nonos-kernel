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

use super::cpuid::{cpuid, cpuid_max_leaf};

pub fn detect_tsc_frequency_cpuid_15h() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x15 { return None; }
    let (eax, ebx, ecx, _) = cpuid(0x15);
    let denominator = eax;
    let numerator = ebx;
    let crystal_freq = ecx;
    if denominator == 0 || numerator == 0 { return None; }
    if crystal_freq != 0 {
        Some((crystal_freq as u64 * numerator as u64) / denominator as u64)
    } else {
        None
    }
}

pub fn detect_frequency_cpuid_16h() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x16 { return None; }
    let (eax, _, _, _) = cpuid(0x16);
    let base_mhz = eax & 0xFFFF;
    if base_mhz > 0 { Some((base_mhz as u64) * 1_000_000) } else { None }
}
