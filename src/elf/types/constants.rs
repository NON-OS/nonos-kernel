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

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

pub mod ident {
    pub const EI_MAG0: usize = 0;
    pub const EI_CLASS: usize = 4;
    pub const EI_DATA: usize = 5;
    pub const EI_VERSION: usize = 6;
    pub const EI_OSABI: usize = 7;
    pub const EI_ABIVERSION: usize = 8;
    pub const EI_PAD: usize = 9;
    pub const EI_NIDENT: usize = 16;
}

pub mod class {
    pub const ELFCLASSNONE: u8 = 0;
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;
}

pub mod data {
    pub const ELFDATANONE: u8 = 0;
    pub const ELFDATA2LSB: u8 = 1;
    pub const ELFDATA2MSB: u8 = 2;
}

pub mod elf_type {
    pub const ET_NONE: u16 = 0;
    pub const ET_REL: u16 = 1;
    pub const ET_EXEC: u16 = 2;
    pub const ET_DYN: u16 = 3;
    pub const ET_CORE: u16 = 4;
}

pub mod machine {
    pub const EM_NONE: u16 = 0;
    pub const EM_386: u16 = 3;
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
    pub const EM_RISCV: u16 = 243;
}

pub mod phdr_type {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
    pub const PT_GNU_EH_FRAME: u32 = 0x6474_E550;
    pub const PT_GNU_STACK: u32 = 0x6474_E551;
    pub const PT_GNU_RELRO: u32 = 0x6474_E552;
}

pub mod phdr_flags {
    pub const PF_X: u32 = 1 << 0;
    pub const PF_W: u32 = 1 << 1;
    pub const PF_R: u32 = 1 << 2;
}

pub mod shdr_type {
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
    pub const SHT_SHLIB: u32 = 10;
    pub const SHT_DYNSYM: u32 = 11;
}

pub mod shdr_flags {
    pub const SHF_WRITE: u64 = 1 << 0;
    pub const SHF_ALLOC: u64 = 1 << 1;
    pub const SHF_EXECINSTR: u64 = 1 << 2;
    pub const SHF_TLS: u64 = 1 << 10;
}

pub mod dyn_tag {
    pub const DT_NULL: u64 = 0;
    pub const DT_NEEDED: u64 = 1;
    pub const DT_PLTRELSZ: u64 = 2;
    pub const DT_PLTGOT: u64 = 3;
    pub const DT_HASH: u64 = 4;
    pub const DT_STRTAB: u64 = 5;
    pub const DT_SYMTAB: u64 = 6;
    pub const DT_RELA: u64 = 7;
    pub const DT_RELASZ: u64 = 8;
    pub const DT_RELAENT: u64 = 9;
    pub const DT_STRSZ: u64 = 10;
    pub const DT_SYMENT: u64 = 11;
    pub const DT_INIT: u64 = 12;
    pub const DT_FINI: u64 = 13;
    pub const DT_SONAME: u64 = 14;
    pub const DT_RPATH: u64 = 15;
    pub const DT_JMPREL: u64 = 23;
    pub const DT_INIT_ARRAY: u64 = 25;
    pub const DT_FINI_ARRAY: u64 = 26;
    pub const DT_INIT_ARRAYSZ: u64 = 27;
    pub const DT_FINI_ARRAYSZ: u64 = 28;
}

pub mod reloc_type {
    pub const R_X86_64_NONE: u32 = 0;
    pub const R_X86_64_64: u32 = 1;
    pub const R_X86_64_PC32: u32 = 2;
    pub const R_X86_64_GOT32: u32 = 3;
    pub const R_X86_64_PLT32: u32 = 4;
    pub const R_X86_64_COPY: u32 = 5;
    pub const R_X86_64_GLOB_DAT: u32 = 6;
    pub const R_X86_64_JUMP_SLOT: u32 = 7;
    pub const R_X86_64_RELATIVE: u32 = 8;
    pub const R_X86_64_GOTPCREL: u32 = 9;
    pub const R_X86_64_32: u32 = 10;
    pub const R_X86_64_32S: u32 = 11;
    pub const R_X86_64_16: u32 = 12;
    pub const R_X86_64_PC16: u32 = 13;
    pub const R_X86_64_8: u32 = 14;
    pub const R_X86_64_PC8: u32 = 15;
    pub const R_X86_64_DTPMOD64: u32 = 16;
    pub const R_X86_64_DTPOFF64: u32 = 17;
    pub const R_X86_64_TPOFF64: u32 = 18;
    pub const R_X86_64_TLSGD: u32 = 19;
    pub const R_X86_64_TLSLD: u32 = 20;
    pub const R_X86_64_DTPOFF32: u32 = 21;
    pub const R_X86_64_GOTTPOFF: u32 = 22;
    pub const R_X86_64_TPOFF32: u32 = 23;
    pub const R_X86_64_IRELATIVE: u32 = 37;
}

pub mod sym_bind {
    pub const STB_LOCAL: u8 = 0;
    pub const STB_GLOBAL: u8 = 1;
    pub const STB_WEAK: u8 = 2;
}

pub mod sym_type {
    pub const STT_NOTYPE: u8 = 0;
    pub const STT_OBJECT: u8 = 1;
    pub const STT_FUNC: u8 = 2;
    pub const STT_SECTION: u8 = 3;
    pub const STT_FILE: u8 = 4;
    pub const STT_TLS: u8 = 6;
}

pub use class as elf_class;
pub use data as elf_data;
pub use machine as elf_machine;
pub use sym_bind as symbol_bind;
pub use sym_type as symbol_type;

pub mod elf_osabi {
    pub const ELFOSABI_NONE: u8 = 0;
    pub const ELFOSABI_SYSV: u8 = 0;
    pub const ELFOSABI_LINUX: u8 = 3;
    pub const ELFOSABI_FREEBSD: u8 = 9;
    pub const ELFOSABI_STANDALONE: u8 = 255;
}
