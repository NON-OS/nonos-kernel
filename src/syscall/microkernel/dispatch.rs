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

//! Numeric router for microkernel syscalls. The contract layer has
//! already verified the capability; this layer only matches a
//! syscall number to its handler and forwards the argument vector.

use super::capability::{sys_cap_check, sys_cap_grant, sys_cap_revoke};
use super::device::{sys_device_claim, sys_device_list, sys_device_release};
use super::dma::{sys_dma_map, sys_dma_unmap};
use super::ipc::{sys_ipc_call, sys_ipc_recv, sys_ipc_send};
use super::irq::{sys_irq_ack, sys_irq_bind, sys_irq_poll, sys_irq_unbind};
use super::memory::{sys_mmap, sys_munmap};
use super::mmio::{sys_mmio_map, sys_mmio_unmap};
use super::numbers::*;
use super::pio::{sys_pio_grant, sys_pio_read, sys_pio_release, sys_pio_write};
use super::process::{sys_exit, sys_spawn, sys_yield};

pub fn dispatch_microkernel_syscall(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    match nr {
        SYS_IPC_SEND => {
            ipc_trace(b"send", a0);
            let r = sys_ipc_send(a0, a1 as *const u8, a2 as usize);
            ipc_trace_ret(b"send", r);
            r
        }
        SYS_IPC_RECV => {
            ipc_trace(b"recv", a0);
            let r = sys_ipc_recv(a0, a1 as *mut u8, a2 as usize, a3);
            ipc_trace_ret(b"recv", r);
            r
        }
        SYS_IPC_CALL => {
            ipc_trace(b"call", a0);
            let r = sys_ipc_call(a0, a1 as *const u8, a2 as usize, a3 as *mut u8, a4 as usize);
            ipc_trace_ret(b"call", r);
            r
        }
        SYS_MMAP => sys_mmap(a0, a1 as usize, a2 as u32, a3 as u32),
        SYS_MUNMAP => sys_munmap(a0, a1 as usize),
        SYS_SPAWN => sys_spawn(a0 as *const u8, a1 as usize),
        SYS_EXIT => sys_exit(a0 as i32),
        SYS_YIELD => sys_yield(),
        SYS_CAP_GRANT => sys_cap_grant(a0 as u32, a1),
        SYS_CAP_REVOKE => sys_cap_revoke(a0 as u32, a1),
        SYS_CAP_CHECK => sys_cap_check(a0 as u32, a1),
        SYS_DEVICE_LIST => sys_device_list(a0 as u32, a1, a2),
        SYS_DEVICE_CLAIM => sys_device_claim(a0),
        SYS_DEVICE_RELEASE => sys_device_release(a0),
        SYS_MMIO_MAP => unpack_mmio_map(a0, a1, a2, a3, a4, a5),
        SYS_MMIO_UNMAP => sys_mmio_unmap(a0),
        SYS_IRQ_BIND => sys_irq_bind(a0, a1, a2 as u32, a3 as u32, a4),
        SYS_IRQ_UNBIND => sys_irq_unbind(a0),
        SYS_IRQ_ACK => sys_irq_ack(a0),
        SYS_IRQ_POLL => sys_irq_poll(a0, a1),
        SYS_DMA_MAP => sys_dma_map(a0, a1, a2, a3 as u32, a4),
        SYS_DMA_UNMAP => sys_dma_unmap(a0),
        SYS_PIO_GRANT => sys_pio_grant(a0, a1, a2 as u8, a3 as u32, a4),
        SYS_PIO_READ => sys_pio_read(a0, a1, a2, a3),
        SYS_PIO_WRITE => sys_pio_write(a0, a1, a2, a3),
        SYS_PIO_RELEASE => sys_pio_release(a0),
        _ => -1,
    }
}

// MkMmioMap carries seven 64-bit inputs but the syscall ABI only
// passes six argument registers. Argument layout:
//
//   a0 = device_id
//   a1 = claim_epoch
//   a2 = (bar_index << 32) | flags
//   a3 = offset
//   a4 = length
//   a5 = out_ptr
//
// `bar_index` is a small integer (0..6 in practice, capped at 255 by
// the BAR table); `flags` is currently zero. Packing them into one
// register keeps offset and length full-width.
fn unpack_mmio_map(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let device_id = a0;
    let claim_epoch = a1;
    let bar_index = ((a2 >> 32) & 0xFFFF_FFFF) as u32;
    let flags = (a2 & 0xFFFF_FFFF) as u32;
    let offset = a3;
    let length = a4;
    sys_mmio_map(device_id, claim_epoch, bar_index, offset, length, flags, a5)
}

fn ipc_trace(kind: &[u8], endpoint: u64) {
    crate::sys::serial::print(b"[IPC ");
    crate::sys::serial::print(kind);
    crate::sys::serial::print(b"] pid=");
    crate::arch::x86_64::diag::print_hex_u64(crate::process::current_pid().unwrap_or(0) as u64);
    crate::sys::serial::print(b" endpoint=");
    crate::arch::x86_64::diag::print_hex_u64(endpoint);
    crate::sys::serial::println(b"");
}

fn ipc_trace_ret(kind: &[u8], r: i64) {
    crate::sys::serial::print(b"[IPC ");
    crate::sys::serial::print(kind);
    crate::sys::serial::print(b"] -> ");
    crate::arch::x86_64::diag::print_hex_u64(r as u64);
    crate::sys::serial::println(b"");
}
