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

pub mod broker;
pub mod crypto;
pub mod debug;
pub mod graphics;
pub mod heap;
pub mod ipc;
pub mod mem;
mod panic;
mod syscall;
mod unistd;

pub use broker::{
    mk_device_claim, mk_device_list, mk_device_release, mk_dma_map, mk_dma_unmap, mk_irq_ack,
    mk_irq_bind, mk_irq_poll, mk_irq_unbind, mk_mmio_map, mk_mmio_unmap, mk_pio_grant, mk_pio_read,
    mk_pio_release, mk_pio_write, Bar, DeviceRecord, DmaMapOut, IrqBindOut, IrqPollOut, MmioMapOut,
    PioGrantOut,
};
pub use crypto::{crypto_decrypt, crypto_ed25519_verify, crypto_encrypt, crypto_random};
pub use debug::mk_debug;
pub use graphics::{
    nonos_cursor_present, nonos_display_dimensions, nonos_display_list, nonos_surface_create,
    nonos_surface_destroy, nonos_surface_map, nonos_surface_present_full,
    nonos_surface_present_rect, NonosDisplayInfo, NONOS_PIXEL_FMT_ARGB8888,
};
pub use heap::{init as heap_init, HeapError};
pub use ipc::{mk_ipc_call, mk_ipc_recv, mk_ipc_send};
pub use mem::mk_mmap;
pub use unistd::{mk_exit, mk_yield};
