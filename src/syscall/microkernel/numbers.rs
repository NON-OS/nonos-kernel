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

//! Microkernel syscall numbers. Mirrors `SyscallNumber::Mk*` enum
//! values so the numeric router has a fixed local set to match
//! against.

pub const SYS_IPC_SEND: u64 = 0x1000;
pub const SYS_IPC_RECV: u64 = 0x1001;
pub const SYS_IPC_CALL: u64 = 0x1002;
pub const SYS_MMAP: u64 = 0x1010;
pub const SYS_MUNMAP: u64 = 0x1011;
pub const SYS_SPAWN: u64 = 0x1020;
pub const SYS_EXIT: u64 = 0x1021;
pub const SYS_YIELD: u64 = 0x1022;
pub const SYS_CAP_GRANT: u64 = 0x1030;
pub const SYS_CAP_REVOKE: u64 = 0x1031;
pub const SYS_CAP_CHECK: u64 = 0x1032;
pub const SYS_DEVICE_LIST: u64 = 0x1040;
pub const SYS_DEVICE_CLAIM: u64 = 0x1041;
pub const SYS_DEVICE_RELEASE: u64 = 0x1042;
pub const SYS_MMIO_MAP: u64 = 0x1043;
pub const SYS_MMIO_UNMAP: u64 = 0x1044;
pub const SYS_IRQ_BIND: u64 = 0x1045;
pub const SYS_IRQ_UNBIND: u64 = 0x1046;
pub const SYS_IRQ_ACK: u64 = 0x1047;
pub const SYS_IRQ_POLL: u64 = 0x1048;
pub const SYS_DMA_MAP: u64 = 0x1049;
pub const SYS_DMA_UNMAP: u64 = 0x104A;
pub const SYS_PIO_GRANT: u64 = 0x104B;
pub const SYS_PIO_READ: u64 = 0x104C;
pub const SYS_PIO_WRITE: u64 = 0x104D;
pub const SYS_PIO_RELEASE: u64 = 0x104E;
pub const SYS_MK_DEBUG: u64 = 0x1050;
