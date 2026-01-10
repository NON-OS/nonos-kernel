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

extern crate alloc;

use alloc::vec::Vec;
use x86_64::VirtAddr;

use super::types::{aux_type, AuxEntry};
use crate::elf::loader::ElfImage;
use crate::elf::types::ProgramHeader;

pub const MAX_AUXV_ENTRIES: usize = 32;
pub const PAGE_SIZE: u64 = 4096;
pub const CLOCK_TICKS_PER_SEC: u64 = 100;

pub struct AuxvBuilder {
    entries: Vec<AuxEntry>,
}

impl AuxvBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_AUXV_ENTRIES),
        }
    }

    pub fn add(&mut self, a_type: u64, a_val: u64) -> &mut Self {
        self.entries.push(AuxEntry::new(a_type, a_val));
        self
    }

    pub fn add_entry(&mut self, entry: AuxEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    pub fn set_phdr(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_PHDR, addr.as_u64())
    }

    pub fn set_phent(&mut self, size: u64) -> &mut Self {
        self.add(aux_type::AT_PHENT, size)
    }

    pub fn set_phnum(&mut self, count: u64) -> &mut Self {
        self.add(aux_type::AT_PHNUM, count)
    }

    pub fn set_pagesz(&mut self, size: u64) -> &mut Self {
        self.add(aux_type::AT_PAGESZ, size)
    }

    pub fn set_base(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_BASE, addr.as_u64())
    }

    pub fn set_flags(&mut self, flags: u64) -> &mut Self {
        self.add(aux_type::AT_FLAGS, flags)
    }

    pub fn set_entry(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_ENTRY, addr.as_u64())
    }

    pub fn set_uid(&mut self, uid: u64) -> &mut Self {
        self.add(aux_type::AT_UID, uid)
    }

    pub fn set_euid(&mut self, euid: u64) -> &mut Self {
        self.add(aux_type::AT_EUID, euid)
    }

    pub fn set_gid(&mut self, gid: u64) -> &mut Self {
        self.add(aux_type::AT_GID, gid)
    }

    pub fn set_egid(&mut self, egid: u64) -> &mut Self {
        self.add(aux_type::AT_EGID, egid)
    }

    pub fn set_platform(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_PLATFORM, addr.as_u64())
    }

    pub fn set_hwcap(&mut self, hwcap: u64) -> &mut Self {
        self.add(aux_type::AT_HWCAP, hwcap)
    }

    pub fn set_hwcap2(&mut self, hwcap2: u64) -> &mut Self {
        self.add(aux_type::AT_HWCAP2, hwcap2)
    }

    pub fn set_clktck(&mut self, ticks: u64) -> &mut Self {
        self.add(aux_type::AT_CLKTCK, ticks)
    }

    pub fn set_secure(&mut self, secure: bool) -> &mut Self {
        self.add(aux_type::AT_SECURE, if secure { 1 } else { 0 })
    }

    pub fn set_random(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_RANDOM, addr.as_u64())
    }

    pub fn set_execfn(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_EXECFN, addr.as_u64())
    }

    pub fn set_sysinfo_ehdr(&mut self, addr: VirtAddr) -> &mut Self {
        self.add(aux_type::AT_SYSINFO_EHDR, addr.as_u64())
    }

    pub fn from_elf_image(image: &ElfImage, phdr_addr: VirtAddr, phnum: u16) -> Self {
        let mut builder = Self::new();
        builder
            .set_phdr(phdr_addr)
            .set_phent(ProgramHeader::SIZE as u64)
            .set_phnum(phnum as u64)
            .set_pagesz(PAGE_SIZE)
            .set_base(image.base_addr)
            .set_entry(image.entry_point)
            .set_flags(0)
            .set_uid(0)
            .set_euid(0)
            .set_gid(0)
            .set_egid(0)
            .set_clktck(CLOCK_TICKS_PER_SEC)
            .set_secure(false);
        builder
    }

    pub fn build(mut self) -> Vec<AuxEntry> {
        self.entries.push(AuxEntry::null());
        self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn size_bytes(&self) -> usize {
        (self.entries.len() + 1) * AuxEntry::SIZE
    }
}

impl Default for AuxvBuilder {
    fn default() -> Self {
        Self::new()
    }
}
