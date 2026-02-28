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

use super::super::constants::{MIN_FREQUENCY, MAX_FREQUENCY};
use super::super::asm::{cpuid, cpuid_max_leaf};

pub fn get_cpuid_frequency() -> Option<u64> {
    let max_leaf = cpuid_max_leaf();
    if max_leaf < 0x15 {
        return None;
    }

    let (eax, ebx, ecx, _) = cpuid(0x15, 0);

    if eax == 0 || ebx == 0 {
        return None;
    }

    let crystal_freq = if ecx != 0 {
        ecx as u64
    } else {
        if max_leaf >= 0x16 {
            let (base_mhz, _, _, _) = cpuid(0x16, 0);
            if base_mhz != 0 {
                return None;
            }
        }
        return None;
    };

    let tsc_freq = (crystal_freq * ebx as u64) / eax as u64;

    if tsc_freq >= MIN_FREQUENCY && tsc_freq <= MAX_FREQUENCY {
        Some(tsc_freq)
    } else {
        None
    }
}
