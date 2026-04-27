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

use super::detect_extended::{detect_extended_ecx, detect_extended_edx};
use super::detect_leaf1::{detect_leaf1_ecx, detect_leaf1_edx};
use super::detect_leaf7::{detect_leaf7_ebx, detect_leaf7_ecx, detect_leaf7_edx};
use super::types::CpuFeatures;
use crate::arch::x86_64::cpu::cpuid::{
    cpuid, cpuid_count, cpuid_max_extended_leaf, cpuid_max_leaf,
};

impl CpuFeatures {
    pub fn detect() -> Self {
        let mut features = Self::new();
        let (_, _, ecx, edx) = cpuid(1);
        detect_leaf1_ecx(&mut features, ecx);
        detect_leaf1_edx(&mut features, edx);
        let max_leaf = cpuid_max_leaf();
        if max_leaf >= 7 {
            let (_, ebx, ecx, edx) = cpuid_count(7, 0);
            detect_leaf7_ebx(&mut features, ebx);
            detect_leaf7_ecx(&mut features, ecx);
            detect_leaf7_edx(&mut features, edx);
        }
        let max_ext = cpuid_max_extended_leaf();
        if max_ext >= 0x80000001 {
            let (_, _, ecx, edx) = cpuid(0x80000001);
            detect_extended_ecx(&mut features, ecx);
            detect_extended_edx(&mut features, edx);
        }
        features
    }
}
