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

mod prot;
mod brk;
mod remap;
mod lock;
mod misc;

pub use prot::{PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, handle_mprotect};
pub use brk::handle_brk;
pub use remap::handle_mremap;
pub use lock::{handle_mlock, handle_mlock2, handle_munlock, handle_mlockall, handle_munlockall};
pub use misc::{handle_msync, handle_mincore, handle_madvise, handle_memfd_create};
