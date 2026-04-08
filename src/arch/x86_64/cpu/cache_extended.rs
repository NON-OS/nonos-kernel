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

use super::cpuid::{cpuid, cpuid_max_extended_leaf};
use super::cache_types::CacheInfo;
use super::cache_assoc::decode_l2_assoc;

pub fn detect_extended() -> CacheInfo {
    let mut info = CacheInfo::default();
    info.line_size = 64;
    let max_ext = cpuid_max_extended_leaf();
    if max_ext >= 0x80000005 {
        let (_, _, ecx, edx) = cpuid(0x80000005);
        info.l1d_line_size = (ecx & 0xFF) as u16;
        info.l1d_assoc = ((ecx >> 16) & 0xFF) as u16;
        info.l1d_size = ((ecx >> 24) & 0xFF) as u32 * 1024;
        info.l1i_line_size = (edx & 0xFF) as u16;
        info.l1i_assoc = ((edx >> 16) & 0xFF) as u16;
        info.l1i_size = ((edx >> 24) & 0xFF) as u32 * 1024;
    }
    if max_ext >= 0x80000006 {
        let (_, _, ecx, edx) = cpuid(0x80000006);
        info.l2_line_size = (ecx & 0xFF) as u16;
        let l2_assoc_enc = ((ecx >> 12) & 0xF) as u8;
        info.l2_assoc = decode_l2_assoc(l2_assoc_enc);
        info.l2_size = ((ecx >> 16) & 0xFFFF) as u32 * 1024;
        info.l3_line_size = (edx & 0xFF) as u16;
        let l3_assoc_enc = ((edx >> 12) & 0xF) as u8;
        info.l3_assoc = decode_l2_assoc(l3_assoc_enc);
        info.l3_size = ((edx >> 18) & 0x3FFF) as u32 * 512 * 1024;
        if info.l2_line_size > 0 {
            info.line_size = info.l2_line_size;
        }
    }
    info
}
