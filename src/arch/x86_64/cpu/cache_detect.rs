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

use super::cache_extended::detect_extended;
use super::cache_types::CacheInfo;
use super::cpuid::{cpuid_count, cpuid_max_leaf};

impl CacheInfo {
    pub fn detect() -> Self {
        let mut info = Self::default();
        info.line_size = 64;
        let max_leaf = cpuid_max_leaf();
        if max_leaf < 4 {
            return detect_extended();
        }
        for subleaf in 0..16 {
            let (eax, ebx, ecx, _) = cpuid_count(4, subleaf);
            let cache_type = (eax & 0x1F) as u8;
            if cache_type == 0 {
                break;
            }
            let level = ((eax >> 5) & 0x7) as u8;
            let line_size = ((ebx & 0xFFF) + 1) as u16;
            let partitions = (((ebx >> 12) & 0x3FF) + 1) as u16;
            let ways = (((ebx >> 22) & 0x3FF) + 1) as u16;
            let sets = ecx + 1;
            let size = (line_size as u32) * (partitions as u32) * (ways as u32) * sets;
            match (level, cache_type) {
                (1, 1) => {
                    info.l1d_size = size;
                    info.l1d_line_size = line_size;
                    info.l1d_assoc = ways;
                }
                (1, 2) => {
                    info.l1i_size = size;
                    info.l1i_line_size = line_size;
                    info.l1i_assoc = ways;
                }
                (2, 3) | (2, 1) => {
                    info.l2_size = size;
                    info.l2_line_size = line_size;
                    info.l2_assoc = ways;
                }
                (3, 3) => {
                    info.l3_size = size;
                    info.l3_line_size = line_size;
                    info.l3_assoc = ways;
                }
                _ => {}
            }
            if line_size > 0 {
                info.line_size = line_size;
            }
        }
        info
    }
}
