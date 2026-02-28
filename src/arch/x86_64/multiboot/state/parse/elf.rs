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

use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::modules::{ElfSection, ElfSections};
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_elf_sections(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ElfSections, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid ELF sections tag.
        unsafe {
            #[repr(C)]
            struct ElfSectionsTag {
                tag_type: u32,
                size: u32,
                num: u32,
                entsize: u32,
                shndx: u32,
            }

            if size < core::mem::size_of::<ElfSectionsTag>() as u32 {
                return Err(MultibootError::ElfSectionError {
                    reason: "Tag too small",
                });
            }

            let tag = &*(tag_ptr as *const ElfSectionsTag);

            let mut sections = Vec::with_capacity(tag.num as usize);
            let section_data_ptr = tag_ptr.add(20);

            for i in 0..tag.num {
                let section_ptr = section_data_ptr.add((i * tag.entsize) as usize);

                #[repr(C)]
                struct Elf64Shdr {
                    sh_name: u32,
                    sh_type: u32,
                    sh_flags: u64,
                    sh_addr: u64,
                    sh_offset: u64,
                    sh_size: u64,
                    sh_link: u32,
                    sh_info: u32,
                    sh_addralign: u64,
                    sh_entsize: u64,
                }

                if tag.entsize >= core::mem::size_of::<Elf64Shdr>() as u32 {
                    let shdr = &*(section_ptr as *const Elf64Shdr);
                    sections.push(ElfSection {
                        name_index: shdr.sh_name,
                        section_type: shdr.sh_type,
                        flags: shdr.sh_flags,
                        addr: shdr.sh_addr,
                        offset: shdr.sh_offset,
                        size: shdr.sh_size,
                        link: shdr.sh_link,
                        info: shdr.sh_info,
                        addralign: shdr.sh_addralign,
                        entsize: shdr.sh_entsize,
                    });
                }
            }

            Ok(ElfSections {
                num: tag.num,
                entsize: tag.entsize,
                shndx: tag.shndx,
                sections,
            })
        }
    }
}
