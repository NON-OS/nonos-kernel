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

use super::attributes::PteFlags;
use super::table::PageTable;

pub const VA_BITS_39: usize = 39;
pub const PA_BITS: usize = 56;
pub const PAGE_SIZE: usize = 4096;
pub const PTE_COUNT: usize = 512;
pub const LEVELS: usize = 3;

pub const VPN_BITS: usize = 9;
pub const VPN_MASK: usize = (1 << VPN_BITS) - 1;
pub const PPN_MASK: u64 = ((1u64 << 44) - 1) << 10;

pub struct Sv39;

impl Sv39 {
    pub fn vpn(va: usize, level: usize) -> usize {
        let shift = 12 + level * VPN_BITS;
        (va >> shift) & VPN_MASK
    }

    pub fn page_offset(va: usize) -> usize {
        va & (PAGE_SIZE - 1)
    }

    pub fn make_pte(ppn: u64, flags: PteFlags) -> u64 {
        (ppn << 10) | flags.bits()
    }

    pub fn pte_ppn(pte: u64) -> u64 {
        (pte >> 10) & ((1 << 44) - 1)
    }

    pub fn pte_flags(pte: u64) -> PteFlags {
        PteFlags(pte & 0xFF)
    }

    pub fn is_valid_va(va: usize) -> bool {
        let sign = va >> (VA_BITS_39 - 1);
        sign == 0 || sign == ((1 << (64 - VA_BITS_39 + 1)) - 1)
    }

    pub fn canonicalize(va: usize) -> usize {
        let sign_bit = (va >> (VA_BITS_39 - 1)) & 1;
        if sign_bit == 1 {
            va | !((1 << VA_BITS_39) - 1)
        } else {
            va & ((1 << VA_BITS_39) - 1)
        }
    }

    pub fn block_size(level: usize) -> usize {
        PAGE_SIZE << (level * VPN_BITS)
    }

    pub fn is_aligned(addr: usize, level: usize) -> bool {
        addr & (Self::block_size(level) - 1) == 0
    }
}

pub const MEGA_PAGE_SIZE: usize = 2 * 1024 * 1024;
pub const GIGA_PAGE_SIZE: usize = 1024 * 1024 * 1024;

pub fn kernel_va_start() -> usize {
    0xFFFF_FFC0_0000_0000
}

pub fn kernel_va_end() -> usize {
    0xFFFF_FFFF_FFFF_FFFF
}

pub fn user_va_start() -> usize {
    0x0000_0000_0000_0000
}

pub fn user_va_end() -> usize {
    0x0000_003F_FFFF_FFFF
}

pub fn is_kernel_va(va: usize) -> bool {
    va >= kernel_va_start()
}

pub fn is_user_va(va: usize) -> bool {
    va <= user_va_end()
}
