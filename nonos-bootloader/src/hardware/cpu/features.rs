// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::super::types::CpuFeatureFlags;

#[cfg(target_arch = "x86_64")]
use super::cpuid::{cpuid, cpuid_subleaf};

pub fn detect_cpu_features() -> CpuFeatureFlags {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut flags = CpuFeatureFlags::default();

        let (_, _, _, edx) = cpuid(0x80000001);
        flags.nxe = (edx & (1 << 20)) != 0;

        let (_, ebx, ecx, _) = cpuid_subleaf(7, 0);
        flags.smep = (ebx & (1 << 7)) != 0;
        flags.smap = (ebx & (1 << 20)) != 0;
        flags.umip = (ecx & (1 << 2)) != 0;

        flags
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        CpuFeatureFlags::default()
    }
}
