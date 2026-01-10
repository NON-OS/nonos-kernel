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

use core::ptr;
use x86_64::VirtAddr;

use crate::elf::errors::{ElfError, ElfResult};

pub const GNU_HASH_BLOOM_SHIFT: u32 = 6;

pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in name {
        if c == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GnuHashHeader {
    pub nbuckets: u32,
    pub symoffset: u32,
    pub bloom_size: u32,
    pub bloom_shift: u32,
}

pub struct GnuHashTable {
    header: GnuHashHeader,
    bloom_filter: VirtAddr,
    buckets: VirtAddr,
    chains: VirtAddr,
    symtab: VirtAddr,
    strtab: VirtAddr,
    strtab_size: usize,
}

impl GnuHashTable {
    pub fn new(
        hash_addr: VirtAddr,
        symtab: VirtAddr,
        strtab: VirtAddr,
        strtab_size: usize,
    ) -> ElfResult<Self> {
        // SAFETY: Caller ensures hash_addr points to valid GNU hash table
        let header = unsafe { ptr::read(hash_addr.as_u64() as *const GnuHashHeader) };

        if header.nbuckets == 0 {
            return Err(ElfError::InvalidHash);
        }

        let bloom_filter = VirtAddr::new(hash_addr.as_u64() + 16);
        let buckets = VirtAddr::new(bloom_filter.as_u64() + (header.bloom_size as u64 * 8));
        let chains = VirtAddr::new(buckets.as_u64() + (header.nbuckets as u64 * 4));
        Ok(Self { header, bloom_filter, buckets, chains, symtab, strtab, strtab_size })
    }

    pub fn lookup(&self, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        let hash = gnu_hash(name_bytes);

        if !self.check_bloom_filter(hash) {
            return None;
        }

        let bucket_idx = (hash % self.header.nbuckets) as usize;

        // SAFETY: Bucket index is within bounds
        let sym_idx = unsafe {
            let bucket_ptr = (self.buckets.as_u64() + (bucket_idx * 4) as u64) as *const u32;
            ptr::read(bucket_ptr) as usize
        };

        if sym_idx == 0 {
            return None;
        }

        if sym_idx < self.header.symoffset as usize {
            return None;
        }

        let chain_offset = sym_idx - self.header.symoffset as usize;
        let mut current_idx = sym_idx;
        let mut chain_pos = chain_offset;

        loop {
            // SAFETY: Chain position is validated by hash table structure
            let chain_entry = unsafe {
                let chain_ptr = (self.chains.as_u64() + (chain_pos * 4) as u64) as *const u32;
                ptr::read(chain_ptr)
            };

            if (chain_entry | 1) == (hash | 1) {
                if self.compare_symbol_name(current_idx, name) {
                    return Some(current_idx);
                }
            }

            if chain_entry & 1 != 0 {
                break;
            }

            current_idx += 1;
            chain_pos += 1;
        }

        None
    }

    fn check_bloom_filter(&self, hash: u32) -> bool {
        let bloom_size = self.header.bloom_size as u64;
        if bloom_size == 0 {
            return true;
        }

        let word_idx = ((hash as u64 / 64) % bloom_size) as usize;
        let bit1 = 1u64 << (hash % 64);
        let bit2 = 1u64 << ((hash >> self.header.bloom_shift) % 64);

        // SAFETY: Word index is within bloom filter bounds
        let bloom_word = unsafe {
            let word_ptr = (self.bloom_filter.as_u64() + (word_idx * 8) as u64) as *const u64;
            ptr::read(word_ptr)
        };

        (bloom_word & bit1 != 0) && (bloom_word & bit2 != 0)
    }

    fn compare_symbol_name(&self, sym_idx: usize, name: &str) -> bool {
        use crate::elf::types::Symbol;

        // SAFETY: Symbol index is validated by hash table lookup
        let sym_ptr =
            unsafe { (self.symtab.as_u64() + (sym_idx * Symbol::SIZE) as u64) as *const Symbol };

        let sym = unsafe { ptr::read(sym_ptr) };

        if sym.st_name as usize >= self.strtab_size {
            return false;
        }

        // SAFETY: String table offset is bounds-checked
        unsafe {
            let str_ptr = (self.strtab.as_u64() + sym.st_name as u64) as *const u8;
            let name_bytes = name.as_bytes();

            for (i, &expected) in name_bytes.iter().enumerate() {
                let actual = *str_ptr.add(i);
                if actual != expected {
                    return false;
                }
            }

            *str_ptr.add(name_bytes.len()) == 0
        }
    }

    pub fn bucket_count(&self) -> u32 {
        self.header.nbuckets
    }

    pub fn sym_offset(&self) -> u32 {
        self.header.symoffset
    }
}
