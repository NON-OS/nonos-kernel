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

pub const HANDOFF_MAGIC: u32 = 0x4E_4F_4E_4F;
pub const HANDOFF_VERSION: u16 = 1;
pub const MAX_CMDLINE_LEN: usize = 4096;

pub fn validate_cmdline_len(len: usize) -> bool {
    len <= MAX_CMDLINE_LEN
}

pub fn truncate_cmdline(cmdline: &str) -> &str {
    if cmdline.len() <= MAX_CMDLINE_LEN {
        cmdline
    } else {
        &cmdline[..MAX_CMDLINE_LEN]
    }
}

pub mod flags {
    pub const WX: u64 = 1 << 0;
    pub const NXE: u64 = 1 << 1;
    pub const SMEP: u64 = 1 << 2;
    pub const SMAP: u64 = 1 << 3;
    pub const UMIP: u64 = 1 << 4;
    pub const IDMAP_PRESERVED: u64 = 1 << 5;
    pub const FB_AVAILABLE: u64 = 1 << 6;
    pub const ACPI_AVAILABLE: u64 = 1 << 7;
    pub const TPM_MEASURED: u64 = 1 << 8;
    pub const SECURE_BOOT: u64 = 1 << 9;
    pub const ZK_ATTESTED: u64 = 1 << 10;

    pub fn flag_names(flags: u64) -> &'static [&'static str] {
        const NAMES: [&str; 11] = [
            "W^X", "NXE", "SMEP", "SMAP", "UMIP", "IDMAP", "FB", "ACPI", "TPM", "SECBOOT", "ZK",
        ];
        &NAMES[..(64 - flags.leading_zeros() as usize).min(11)]
    }
}

pub mod pixel_format {
    pub const RGB: u32 = 0;
    pub const BGR: u32 = 1;
    pub const RGBX: u32 = 2;
    pub const BGRX: u32 = 3;
}
