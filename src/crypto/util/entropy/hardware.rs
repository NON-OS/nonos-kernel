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

use core::arch::x86_64::__cpuid;
use super::state::ENTROPY_SOURCE;

pub fn init() {
    // SAFETY: single-threaded initialization during early boot
    unsafe {
        let cpuid = __cpuid(1);
        ENTROPY_SOURCE.rdrand_available = (cpuid.ecx & (1 << 30)) != 0;

        let cpuid_ext = __cpuid_count(7, 0);
        ENTROPY_SOURCE.rdseed_available = (cpuid_ext.ebx & (1 << 18)) != 0;
    }
}

pub(crate) fn rdrand64() -> Option<u64> {
    // SAFETY: reading global state after init
    unsafe {
        if !ENTROPY_SOURCE.rdrand_available {
            return None;
        }

        let mut val: u64;
        let mut success: u8;

        // SAFETY: RDRAND is checked available via CPUID
        core::arch::asm!(
            "rdrand {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );

        if success != 0 {
            Some(val)
        } else {
            None
        }
    }
}

pub(crate) fn rdseed64() -> Option<u64> {
    // SAFETY: reading global state after init
    unsafe {
        if !ENTROPY_SOURCE.rdseed_available {
            return None;
        }

        let mut val: u64;
        let mut success: u8;

        // SAFETY: RDSEED is checked available via CPUID
        core::arch::asm!(
            "rdseed {val}",
            "setc {success}",
            val = out(reg) val,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );

        if success != 0 {
            Some(val)
        } else {
            None
        }
    }
}

pub fn has_hardware_rng() -> bool {
    // SAFETY: reading global state after init
    unsafe {
        ENTROPY_SOURCE.rdrand_available || ENTROPY_SOURCE.rdseed_available
    }
}

fn __cpuid_count(leaf: u32, subleaf: u32) -> core::arch::x86_64::CpuidResult {
    core::arch::x86_64::__cpuid_count(leaf, subleaf)
}
