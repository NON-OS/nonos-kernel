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

mod elf_constants;
mod elf_structs;
mod elf_loaded;
mod elf_error;
mod types;
mod parser;
pub mod validate;
pub mod load_segment;
pub mod load_phdr;
mod loader;
mod relocations;
pub mod symbols;
mod auxv;
mod api;

pub use types::*;
pub use parser::*;
pub use loader::*;
pub use relocations::*;
pub use auxv::*;
pub use api::*;
pub use validate::{USER_SPACE_END, validate_user_address, validate_wx_segment, validate_alignment};
pub use load_segment::{map_segment_pages, copy_segment_data};
pub use load_phdr::{load_interp, handle_gnu_stack, find_phdr_addr};
pub use symbols::{resolve_symbol, get_symbol_by_index};
