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

use crate::syscall::microkernel::mmio::sys_mmio_map;

// MkMmioMap carries seven 64-bit inputs but the syscall ABI only
// passes six argument registers. Packing layout:
//
//   a0 = device_id
//   a1 = claim_epoch
//   a2 = (bar_index << 32) | flags
//   a3 = offset
//   a4 = length
//   a5 = out_ptr
//
// `bar_index` is small (0..6 in practice, capped at 255 by the BAR
// table); `flags` is currently zero. Packing them into one register
// keeps offset and length full-width.
pub(super) fn mmio_map(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let device_id = a0;
    let claim_epoch = a1;
    let bar_index = ((a2 >> 32) & 0xFFFF_FFFF) as u32;
    let flags = (a2 & 0xFFFF_FFFF) as u32;
    let offset = a3;
    let length = a4;
    sys_mmio_map(device_id, claim_epoch, bar_index, offset, length, flags, a5)
}
