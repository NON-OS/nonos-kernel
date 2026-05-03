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

mod bridge;
mod numbers;
mod raw;

pub(crate) use bridge::{call_diverging, call_raw};
pub use numbers::N_RT_SIGRETURN;
pub(crate) use numbers::{
    N_BRK, N_CRYPTO_DECRYPT, N_CRYPTO_ENCRYPT, N_CRYPTO_RANDOM, N_EXIT,
    N_GFX_DISPLAY_DIMENSIONS, N_GFX_SURFACE_CREATE, N_GFX_SURFACE_DESTROY, N_GFX_SURFACE_MAP,
    N_GFX_SURFACE_PRESENT_FULL, N_MK_IPC_CALL, N_MK_IPC_RECV, N_MK_IPC_SEND, N_MMAP, N_READ,
    N_WRITE,
};
