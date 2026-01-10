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
use crate::elf::types::{reloc_type, Rela};

pub struct RelocationProcessor {
    base_addr: VirtAddr,
}

impl RelocationProcessor {
    pub fn new(base_addr: VirtAddr) -> Self {
        Self { base_addr }
    }

    pub fn process_rela(
        &self,
        rela_addr: VirtAddr,
        rela_count: usize,
        symbol_resolver: impl Fn(usize) -> Option<u64>,
    ) -> ElfResult<usize> {
        let mut processed = 0;

        for i in 0..rela_count {
            let rela_ptr =
                (rela_addr.as_u64() + (i * core::mem::size_of::<Rela>()) as u64) as *const Rela;

            // SAFETY: Caller ensures rela table is valid
            let rela = unsafe { ptr::read(rela_ptr) };

            let sym_idx = (rela.r_info >> 32) as usize;
            let rel_type = (rela.r_info & 0xFFFFFFFF) as u32;

            let target_addr = self.base_addr.as_u64() + rela.r_offset;

            match rel_type {
                reloc_type::R_X86_64_NONE => {}

                reloc_type::R_X86_64_64 => {
                    if let Some(sym_val) = symbol_resolver(sym_idx) {
                        let value = sym_val.wrapping_add(rela.r_addend as u64);
                        // SAFETY: Target address is within loaded image
                        unsafe {
                            ptr::write(target_addr as *mut u64, value);
                        }
                        processed += 1;
                    }
                }

                reloc_type::R_X86_64_GLOB_DAT | reloc_type::R_X86_64_JUMP_SLOT => {
                    if let Some(sym_val) = symbol_resolver(sym_idx) {
                        // SAFETY: Target address is within GOT
                        unsafe {
                            ptr::write(target_addr as *mut u64, sym_val);
                        }
                        processed += 1;
                    }
                }

                reloc_type::R_X86_64_RELATIVE => {
                    let value = self.base_addr.as_u64().wrapping_add(rela.r_addend as u64);
                    // SAFETY: Target address is within loaded image
                    unsafe {
                        ptr::write(target_addr as *mut u64, value);
                    }
                    processed += 1;
                }

                reloc_type::R_X86_64_COPY => {
                    if let Some(sym_val) = symbol_resolver(sym_idx) {
                        // SAFETY: Both addresses are valid and non-overlapping
                        unsafe {
                            let src = sym_val as *const u8;
                            let dst = target_addr as *mut u8;
                            let size = self.get_symbol_size(sym_idx);
                            ptr::copy_nonoverlapping(src, dst, size);
                        }
                        processed += 1;
                    }
                }

                reloc_type::R_X86_64_TPOFF64 => {
                    if let Some(sym_val) = symbol_resolver(sym_idx) {
                        let value = sym_val.wrapping_add(rela.r_addend as u64);
                        // SAFETY: Target address is within TLS area
                        unsafe {
                            ptr::write(target_addr as *mut u64, value);
                        }
                        processed += 1;
                    }
                }

                reloc_type::R_X86_64_DTPMOD64 => {
                    // SAFETY: Target address is within loaded image
                    unsafe {
                        ptr::write(target_addr as *mut u64, 1);
                    }
                    processed += 1;
                }

                reloc_type::R_X86_64_DTPOFF64 => {
                    if let Some(sym_val) = symbol_resolver(sym_idx) {
                        let value = sym_val.wrapping_add(rela.r_addend as u64);
                        // SAFETY: Target address is within loaded image
                        unsafe {
                            ptr::write(target_addr as *mut u64, value);
                        }
                        processed += 1;
                    }
                }

                reloc_type::R_X86_64_IRELATIVE => {
                    let resolver_addr = self.base_addr.as_u64().wrapping_add(rela.r_addend as u64);
                    // SAFETY: Target address is within loaded image
                    unsafe {
                        ptr::write(target_addr as *mut u64, resolver_addr);
                    }
                    processed += 1;
                }

                _ => {
                    return Err(ElfError::UnsupportedRelocation(rel_type));
                }
            }
        }

        Ok(processed)
    }

    pub fn process_plt_relocations(
        &self,
        plt_rela_addr: VirtAddr,
        plt_rela_count: usize,
        symbol_resolver: impl Fn(usize) -> Option<u64>,
    ) -> ElfResult<usize> {
        let mut processed = 0;

        for i in 0..plt_rela_count {
            let rela_ptr =
                (plt_rela_addr.as_u64() + (i * core::mem::size_of::<Rela>()) as u64) as *const Rela;

            // SAFETY: Caller ensures PLT rela table is valid
            let rela = unsafe { ptr::read(rela_ptr) };

            let sym_idx = (rela.r_info >> 32) as usize;
            let rel_type = (rela.r_info & 0xFFFFFFFF) as u32;

            if rel_type != reloc_type::R_X86_64_JUMP_SLOT {
                continue;
            }

            let target_addr = self.base_addr.as_u64() + rela.r_offset;

            if let Some(sym_val) = symbol_resolver(sym_idx) {
                // SAFETY: Target address is within GOT.PLT
                unsafe {
                    ptr::write(target_addr as *mut u64, sym_val);
                }
                processed += 1;
            }
        }

        Ok(processed)
    }

    fn get_symbol_size(&self, _sym_idx: usize) -> usize {
        8
    }
}

pub fn apply_single_relocation(
    target: VirtAddr,
    rel_type: u32,
    symbol_value: u64,
    addend: i64,
    base_addr: VirtAddr,
) -> ElfResult<()> {
    match rel_type {
        reloc_type::R_X86_64_NONE => Ok(()),

        reloc_type::R_X86_64_64 => {
            let value = symbol_value.wrapping_add(addend as u64);
            // SAFETY: Caller ensures target address is valid
            unsafe {
                ptr::write(target.as_u64() as *mut u64, value);
            }
            Ok(())
        }

        reloc_type::R_X86_64_GLOB_DAT | reloc_type::R_X86_64_JUMP_SLOT => {
            // SAFETY: Caller ensures target address is valid
            unsafe {
                ptr::write(target.as_u64() as *mut u64, symbol_value);
            }
            Ok(())
        }

        reloc_type::R_X86_64_RELATIVE => {
            let value = base_addr.as_u64().wrapping_add(addend as u64);
            // SAFETY: Caller ensures target address is valid
            unsafe {
                ptr::write(target.as_u64() as *mut u64, value);
            }
            Ok(())
        }

        reloc_type::R_X86_64_TPOFF64 => {
            let value = symbol_value.wrapping_add(addend as u64);
            // SAFETY: Caller ensures target address is valid
            unsafe {
                ptr::write(target.as_u64() as *mut u64, value);
            }
            Ok(())
        }

        _ => Err(ElfError::UnsupportedRelocation(rel_type)),
    }
}
