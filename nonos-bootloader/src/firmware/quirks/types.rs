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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuirkFlags {
    bits: u32,
}

impl QuirkFlags {
    pub const NONE: Self = Self { bits: 0 };
    pub const MMAP_UNSTABLE: Self = Self { bits: 1 << 0 };
    pub const GOP_LATE_INIT: Self = Self { bits: 1 << 1 };
    pub const TPM_SLOW: Self = Self { bits: 1 << 2 };
    pub const ACPI_BROKEN: Self = Self { bits: 1 << 3 };
    pub const EBS_RETRY_NEEDED: Self = Self { bits: 1 << 4 };
    pub const NX_DISABLED: Self = Self { bits: 1 << 5 };

    pub const fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FirmwareQuirk {
    pub vendor: &'static str,
    pub model: &'static str,
    pub flags: QuirkFlags,
}

pub static KNOWN_QUIRKS: &[FirmwareQuirk] = &[
    FirmwareQuirk {
        vendor: "American Megatrends",
        model: "",
        flags: QuirkFlags::MMAP_UNSTABLE,
    },
    FirmwareQuirk {
        vendor: "InsydeH2O",
        model: "",
        flags: QuirkFlags::EBS_RETRY_NEEDED,
    },
    FirmwareQuirk {
        vendor: "Phoenix",
        model: "",
        flags: QuirkFlags::GOP_LATE_INIT,
    },
];
