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

mod api;
mod auxv;
mod elf_constants;
mod elf_error;
mod elf_loaded;
mod elf_structs;
pub mod load_phdr;
pub mod load_segment;
mod loader;
mod parser;
mod relocations;
pub mod symbols;
mod types;
pub mod validate;

pub use api::*;
pub use auxv::*;
pub use load_phdr::{find_phdr_addr, handle_gnu_stack, load_interp};
pub use load_segment::{copy_segment_data, map_segment_pages};
pub use loader::*;
pub use parser::*;
pub use relocations::*;
pub use symbols::{get_symbol_by_index, resolve_symbol};
pub use types::*;
pub use validate::{
    validate_alignment, validate_user_address, validate_wx_segment, USER_SPACE_END,
};
