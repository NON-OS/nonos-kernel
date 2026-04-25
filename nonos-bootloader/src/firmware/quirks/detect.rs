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

use uefi::prelude::*;
use super::types::{QuirkFlags, KNOWN_QUIRKS};

pub fn detect_firmware_quirks(st: &SystemTable<Boot>) -> QuirkFlags {
    let vendor = get_firmware_vendor(st);
    let mut flags = QuirkFlags::NONE;
    for quirk in KNOWN_QUIRKS {
        if vendor_matches(&vendor, quirk.vendor) { flags = flags.union(quirk.flags); }
    }
    if needs_ebs_retry(st) { flags = flags.union(QuirkFlags::EBS_RETRY_NEEDED); }
    flags
}

fn get_firmware_vendor(st: &SystemTable<Boot>) -> alloc::string::String {
    st.firmware_vendor().map(|v| alloc::string::String::from_utf16_lossy(v.as_slice_with_nul().iter().take_while(|&&c| c != 0).map(|c| c.to_u16()).collect::<alloc::vec::Vec<_>>().as_slice())).unwrap_or_default()
}

fn vendor_matches(vendor: &str, pattern: &str) -> bool {
    vendor.to_lowercase().contains(&pattern.to_lowercase())
}

fn needs_ebs_retry(st: &SystemTable<Boot>) -> bool {
    let vendor = get_firmware_vendor(st);
    vendor.contains("AMI") && st.firmware_revision() < 0x00050000
}
