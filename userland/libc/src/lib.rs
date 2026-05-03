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

#![no_std]

pub mod crypto;
pub mod graphics;
pub mod heap;
pub mod ipc;
pub mod mem;
mod panic;
pub mod signal;
mod syscall;
mod unistd;

pub use crypto::{crypto_decrypt, crypto_encrypt, crypto_random};
pub use graphics::{
    nonos_display_dimensions, nonos_surface_create, nonos_surface_destroy, nonos_surface_map,
    NONOS_PIXEL_FMT_ARGB8888,
};
pub use heap::{init as heap_init, HeapError};
pub use ipc::{mk_ipc_call, mk_ipc_recv, mk_ipc_send};
pub use mem::{brk, mmap};
pub use signal::__nonos_rt_sigreturn;
pub use unistd::{_exit, read, write};
