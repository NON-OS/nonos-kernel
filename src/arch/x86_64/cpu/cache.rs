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

use super::cpuid::{cpuid, cpuid_count, cpuid_max_leaf, cpuid_max_extended_leaf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheType {
    Null = 0,
    Data = 1,
    Instruction = 2,
    Unified = 3,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheLevel {
    pub cache_type: u8,
    pub level: u8,
    pub self_init: bool,
    pub fully_assoc: bool,
    pub max_threads: u16,
    pub max_cores: u16,
    pub line_size: u16,
    pub partitions: u16,
    pub ways: u16,
    pub sets: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheInfo {
    pub l1d_size: u32,
    pub l1d_line_size: u16,
    pub l1d_assoc: u16,
    pub l1i_size: u32,
    pub l1i_line_size: u16,
    pub l1i_assoc: u16,
    pub l2_size: u32,
    pub l2_line_size: u16,
    pub l2_assoc: u16,
    pub l3_size: u32,
    pub l3_line_size: u16,
    pub l3_assoc: u16,
    pub line_size: u16,
}

impl CacheInfo {
    pub fn detect() -> Self {
        let mut info = Self::default();
        info.line_size = 64;

        let max_leaf = cpuid_max_leaf();
        if max_leaf < 4 {
            return Self::detect_extended();
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

    fn detect_extended() -> Self {
        let mut info = Self::default();
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
}

pub fn decode_l2_assoc(encoded: u8) -> u16 {
    match encoded {
        0 => 0,
        1 => 1,
        2 => 2,
        4 => 4,
        6 => 8,
        8 => 16,
        10 => 32,
        11 => 48,
        12 => 64,
        13 => 96,
        14 => 128,
        15 => 0,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_assoc_decode() {
        assert_eq!(decode_l2_assoc(1), 1);
        assert_eq!(decode_l2_assoc(2), 2);
        assert_eq!(decode_l2_assoc(6), 8);
        assert_eq!(decode_l2_assoc(8), 16);
    }
}
