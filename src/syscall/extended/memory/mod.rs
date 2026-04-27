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

mod brk;
mod lock;
mod misc;
mod prot;
mod remap;

pub use brk::handle_brk;
pub use lock::*;
pub use misc::{handle_madvise, handle_memfd_create, handle_mincore, handle_msync};
pub use prot::{handle_mprotect, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
pub use remap::handle_mremap;
