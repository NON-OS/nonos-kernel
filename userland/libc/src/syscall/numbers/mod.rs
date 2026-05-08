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

// NØNOS microkernel syscall numbers used by userland. Every value
// must match the kernel side
// (`crate::syscall::numbers::SyscallNumber` /
// `microkernel::numbers::SYS_*`). The static gate
// `tools/ci/run-static-checks.sh` re-checks the critical pairs.

pub(crate) const N_MK_IPC_SEND: i64 = 0x1000;
pub(crate) const N_MK_IPC_RECV: i64 = 0x1001;
pub(crate) const N_MK_IPC_CALL: i64 = 0x1002;

pub(crate) const N_MMAP: i64 = 0x1010;

pub(crate) const N_EXIT: i64 = 0x1021;
pub(crate) const N_MK_YIELD: i64 = 0x1022;

pub(crate) const N_CRYPTO_RANDOM: i64 = 900;
pub(crate) const N_CRYPTO_ENCRYPT: i64 = 904;
pub(crate) const N_CRYPTO_DECRYPT: i64 = 905;
pub(crate) const N_CRYPTO_ED25519_VERIFY: i64 = 909;

pub(crate) const N_GFX_DISPLAY_DIMENSIONS: i64 = 1300;
pub(crate) const N_GFX_SURFACE_CREATE: i64 = 1301;
pub(crate) const N_GFX_SURFACE_DESTROY: i64 = 1302;
pub(crate) const N_GFX_SURFACE_MAP: i64 = 1303;
pub(crate) const N_GFX_SURFACE_PRESENT_FULL: i64 = 1304;
pub(crate) const N_GFX_SURFACE_PRESENT_RECT: i64 = 1305;
pub(crate) const N_GFX_DISPLAY_LIST: i64 = 1306;
pub(crate) const N_GFX_CURSOR_PRESENT: i64 = 1309;

pub(crate) const N_MK_DEVICE_LIST: i64 = 0x1040;
pub(crate) const N_MK_DEVICE_CLAIM: i64 = 0x1041;
pub(crate) const N_MK_DEVICE_RELEASE: i64 = 0x1042;
pub(crate) const N_MK_MMIO_MAP: i64 = 0x1043;
pub(crate) const N_MK_MMIO_UNMAP: i64 = 0x1044;
pub(crate) const N_MK_IRQ_BIND: i64 = 0x1045;
pub(crate) const N_MK_IRQ_UNBIND: i64 = 0x1046;
pub(crate) const N_MK_IRQ_ACK: i64 = 0x1047;
pub(crate) const N_MK_IRQ_POLL: i64 = 0x1048;
pub(crate) const N_MK_DMA_MAP: i64 = 0x1049;
pub(crate) const N_MK_DMA_UNMAP: i64 = 0x104A;
pub(crate) const N_MK_PIO_GRANT: i64 = 0x104B;
pub(crate) const N_MK_PIO_READ: i64 = 0x104C;
pub(crate) const N_MK_PIO_WRITE: i64 = 0x104D;
pub(crate) const N_MK_PIO_RELEASE: i64 = 0x104E;

pub(crate) const N_MK_DEBUG: i64 = 0x1050;
