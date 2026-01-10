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
use crate::elf::types::Symbol;

pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        if c == 0 {
            break;
        }
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysvHashHeader {
    pub nbuckets: u32,
    pub nchains: u32,
}

pub struct SysvHashTable {
    header: SysvHashHeader,
    buckets: VirtAddr,
    chains: VirtAddr,
    symtab: VirtAddr,
    strtab: VirtAddr,
    strtab_size: usize,
}

impl SysvHashTable {
    pub fn new(
        hash_addr: VirtAddr,
        symtab: VirtAddr,
        strtab: VirtAddr,
        strtab_size: usize,
    ) -> ElfResult<Self> {
        // SAFETY: Caller ensures hash_addr points to valid SYSV hash table
        let header = unsafe { ptr::read(hash_addr.as_u64() as *const SysvHashHeader) };

        if header.nbuckets == 0 {
            return Err(ElfError::InvalidHash);
        }

        let buckets = VirtAddr::new(hash_addr.as_u64() + 8);
        let chains = VirtAddr::new(buckets.as_u64() + (header.nbuckets as u64 * 4));

        Ok(Self { header, buckets, chains, symtab, strtab, strtab_size })
    }

    pub fn lookup(&self, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        let hash = sysv_hash(name_bytes);
        let bucket_idx = (hash % self.header.nbuckets) as usize;

        // SAFETY: Bucket index is within bounds
        let mut sym_idx = unsafe {
            let bucket_ptr = (self.buckets.as_u64() + (bucket_idx * 4) as u64) as *const u32;
            ptr::read(bucket_ptr) as usize
        };

        while sym_idx != 0 {
            if sym_idx >= self.header.nchains as usize {
                break;
            }

            if self.compare_symbol_name(sym_idx, name) {
                return Some(sym_idx);
            }

            // SAFETY: Symbol index is within chain bounds
            sym_idx = unsafe {
                let chain_ptr = (self.chains.as_u64() + (sym_idx * 4) as u64) as *const u32;
                ptr::read(chain_ptr) as usize
            };
        }

        None
    }

    fn compare_symbol_name(&self, sym_idx: usize, name: &str) -> bool {
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

    pub fn chain_count(&self) -> u32 {
        self.header.nchains
    }

    pub fn symbol_count(&self) -> usize {
        self.header.nchains as usize
    }
}
