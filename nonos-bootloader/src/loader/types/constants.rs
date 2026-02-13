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

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub mod elf_class {
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;
}

pub mod elf_data {
    pub const ELFDATA2LSB: u8 = 1;
    pub const ELFDATA2MSB: u8 = 2;
}

pub mod elf_osabi {
    pub const ELFOSABI_NONE: u8 = 0;
    pub const ELFOSABI_LINUX: u8 = 3;
    pub const ELFOSABI_STANDALONE: u8 = 255;
}

pub mod elf_type {
    pub const ET_NONE: u16 = 0;
    pub const ET_REL: u16 = 1;
    pub const ET_EXEC: u16 = 2;
    pub const ET_DYN: u16 = 3;
    pub const ET_CORE: u16 = 4;
}

pub mod elf_machine {
    pub const EM_NONE: u16 = 0;
    pub const EM_386: u16 = 3;
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
    pub const EM_RISCV: u16 = 243;
}

pub mod ph_type {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
    pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
    pub const PT_GNU_STACK: u32 = 0x6474e551;
    pub const PT_GNU_RELRO: u32 = 0x6474e552;
}

pub mod ph_flags {
    pub const PF_X: u32 = 1;
    pub const PF_W: u32 = 2;
    pub const PF_R: u32 = 4;
}

pub mod sh_type {
    pub const SHT_NULL: u32 = 0;
    pub const SHT_PROGBITS: u32 = 1;
    pub const SHT_SYMTAB: u32 = 2;
    pub const SHT_STRTAB: u32 = 3;
    pub const SHT_RELA: u32 = 4;
    pub const SHT_HASH: u32 = 5;
    pub const SHT_DYNAMIC: u32 = 6;
    pub const SHT_NOTE: u32 = 7;
    pub const SHT_NOBITS: u32 = 8;
    pub const SHT_REL: u32 = 9;
    pub const SHT_DYNSYM: u32 = 11;
    pub const SHT_INIT_ARRAY: u32 = 14;
    pub const SHT_FINI_ARRAY: u32 = 15;
    pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
}

pub mod dyn_tag {
    pub const DT_NULL: i64 = 0;
    pub const DT_NEEDED: i64 = 1;
    pub const DT_PLTRELSZ: i64 = 2;
    pub const DT_PLTGOT: i64 = 3;
    pub const DT_HASH: i64 = 4;
    pub const DT_STRTAB: i64 = 5;
    pub const DT_SYMTAB: i64 = 6;
    pub const DT_RELA: i64 = 7;
    pub const DT_RELASZ: i64 = 8;
    pub const DT_RELAENT: i64 = 9;
    pub const DT_STRSZ: i64 = 10;
    pub const DT_SYMENT: i64 = 11;
    pub const DT_INIT: i64 = 12;
    pub const DT_FINI: i64 = 13;
    pub const DT_SONAME: i64 = 14;
    pub const DT_RPATH: i64 = 15;
    pub const DT_SYMBOLIC: i64 = 16;
    pub const DT_REL: i64 = 17;
    pub const DT_RELSZ: i64 = 18;
    pub const DT_RELENT: i64 = 19;
    pub const DT_PLTREL: i64 = 20;
    pub const DT_DEBUG: i64 = 21;
    pub const DT_TEXTREL: i64 = 22;
    pub const DT_JMPREL: i64 = 23;
    pub const DT_BIND_NOW: i64 = 24;
    pub const DT_INIT_ARRAY: i64 = 25;
    pub const DT_FINI_ARRAY: i64 = 26;
    pub const DT_INIT_ARRAYSZ: i64 = 27;
    pub const DT_FINI_ARRAYSZ: i64 = 28;
    pub const DT_GNU_HASH: i64 = 0x6ffffef5;
    pub const DT_RELACOUNT: i64 = 0x6ffffff9;
    pub const DT_RELCOUNT: i64 = 0x6ffffffa;
    pub const DT_FLAGS_1: i64 = 0x6ffffffb;
}

pub mod memory {
    pub const PAGE_SIZE: usize = 0x1000;
    pub const PAGE_SHIFT: usize = 12;
    pub const PAGE_MASK: usize = PAGE_SIZE - 1;
    pub const MAX_KERNEL_SIZE: usize = 256 * 1024 * 1024;
    pub const MIN_LOAD_ADDRESS: u64 = 0x4000000; // 64MB well above UEFI/ACPI regions
    pub const MAX_LOAD_ADDRESS: u64 = 0x1_0000_0000 - (256 * 1024 * 1024);
    pub const MAX_LOAD_SEGMENTS: usize = 32;
    pub const MAX_ALLOCATIONS: usize = 64;

    #[inline]
    pub const fn page_align_down(addr: u64) -> u64 {
        addr & !(PAGE_SIZE as u64 - 1)
    }

    #[inline]
    pub const fn page_align_up(addr: u64) -> u64 {
        (addr + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
    }

    #[inline]
    pub const fn pages_needed(size: usize) -> usize {
        (size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}
