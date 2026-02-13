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

pub mod constants;
pub mod dynamic;
pub mod header;
pub mod program;
pub mod section;
pub mod segment;
pub mod symbol;

pub use constants::{
    dyn_tag, elf_class, elf_data, elf_machine, elf_osabi, elf_type, memory, ph_flags, ph_type,
    sh_type, ELF_MAGIC,
};

pub use dynamic::{DynamicInfo, Elf64Dyn};
pub use header::Elf64Header;
pub use program::Elf64Phdr;
pub use section::{Elf64Shdr, SHF_ALLOC, SHF_EXECINSTR, SHF_TLS, SHF_WRITE};
pub use segment::LoadedSegment;
pub use symbol::{
    elf64_st_info, Elf64Sym, SHN_ABS, SHN_COMMON, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK,
    STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION, STT_TLS, STV_DEFAULT, STV_HIDDEN,
};
