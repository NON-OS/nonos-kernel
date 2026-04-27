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

use uefi::table::boot::{MemoryDescriptor, MemoryType};

use super::types::QuirkFlags;

pub fn apply_mmap_quirks(entry: &MemoryDescriptor, quirks: QuirkFlags) -> bool {
    if quirks.contains(QuirkFlags::MMAP_UNSTABLE) {
        if is_suspicious_entry(entry) {
            return false;
        }
    }
    true
}

fn is_suspicious_entry(entry: &MemoryDescriptor) -> bool {
    if entry.page_count == 0 {
        return true;
    }

    if entry.phys_start > 0xFFFF_FFFF_FFFF_0000 {
        return true;
    }

    let end = entry.phys_start.saturating_add(entry.page_count.saturating_mul(4096));
    if end < entry.phys_start {
        return true;
    }

    if entry.ty == MemoryType::RESERVED && entry.page_count > 0x100000 {
        return true;
    }

    false
}
