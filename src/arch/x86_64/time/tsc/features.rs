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

use super::types::TscFeatures;
use super::asm::{cpuid, cpuid_max_leaf, cpuid_max_extended_leaf};
use super::state::FEATURES;

pub fn detect_features() -> TscFeatures {
    let max_leaf = cpuid_max_leaf();
    let max_ext = cpuid_max_extended_leaf();

    let (_, _, ecx_01, edx_01) = if max_leaf >= 1 {
        cpuid(1, 0)
    } else {
        (0, 0, 0, 0)
    };

    let (_, ebx_07, _, _) = if max_leaf >= 7 {
        cpuid(7, 0)
    } else {
        (0, 0, 0, 0)
    };

    let (_, _, _, edx_ext1) = if max_ext >= 0x80000001 {
        cpuid(0x80000001, 0)
    } else {
        (0, 0, 0, 0)
    };

    let (_, _, _, edx_ext7) = if max_ext >= 0x80000007 {
        cpuid(0x80000007, 0)
    } else {
        (0, 0, 0, 0)
    };

    let (_, _, _, _edx_06) = if max_leaf >= 6 {
        cpuid(6, 0)
    } else {
        (0, 0, 0, 0)
    };

    TscFeatures {
        tsc_available: (edx_01 & (1 << 4)) != 0,
        rdtscp_available: (edx_ext1 & (1 << 27)) != 0,
        invariant_tsc: (edx_ext7 & (1 << 8)) != 0,
        deadline_mode: (ecx_01 & (1 << 24)) != 0,
        cpuid_frequency: max_leaf >= 0x15,
        tsc_adjust: (ebx_07 & (1 << 1)) != 0,
        always_running: (edx_ext7 & (1 << 8)) != 0,
    }
}

pub fn is_tsc_available() -> bool {
    FEATURES.read().tsc_available
}

pub fn is_invariant() -> bool {
    FEATURES.read().invariant_tsc
}

pub fn has_rdtscp() -> bool {
    FEATURES.read().rdtscp_available
}

pub fn has_deadline_mode() -> bool {
    FEATURES.read().deadline_mode
}

pub fn get_features() -> TscFeatures {
    *FEATURES.read()
}
