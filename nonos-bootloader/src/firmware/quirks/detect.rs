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

use uefi::prelude::*;
use uefi::table::cfg::SMBIOS3_GUID;

use super::types::{QuirkFlags, KNOWN_QUIRKS};

pub fn detect_firmware_quirks(st: &SystemTable<Boot>) -> QuirkFlags {
    let vendor = get_firmware_vendor(st);
    let mut flags = QuirkFlags::NONE;

    for quirk in KNOWN_QUIRKS {
        if vendor_matches(&vendor, quirk.vendor) {
            flags = flags.union(quirk.flags);
        }
    }

    if needs_ebs_retry(st) {
        flags = flags.union(QuirkFlags::EBS_RETRY_NEEDED);
    }

    flags
}

fn get_firmware_vendor(st: &SystemTable<Boot>) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let vendor = st.firmware_vendor();
    for (i, ch) in vendor.iter().take(63).enumerate() {
        buf[i] = u16::from(*ch) as u8;
    }
    buf
}

fn vendor_matches(vendor: &[u8; 64], pattern: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    if pattern_bytes.is_empty() {
        return false;
    }
    vendor.windows(pattern_bytes.len()).any(|w| w == pattern_bytes)
}

fn needs_ebs_retry(st: &SystemTable<Boot>) -> bool {
    for entry in st.config_table() {
        if entry.guid == SMBIOS3_GUID {
            return false;
        }
    }
    true
}
