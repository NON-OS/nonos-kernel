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

//! MMIO mapping. Cap requirement: `Mmio`. The kernel packs
//! `bar_index` and `flags` into a single argument register so the
//! ABI stays inside the six-word syscall envelope.

use super::types::MmioMapOut;
use crate::syscall::{call_raw, N_MK_MMIO_MAP, N_MK_MMIO_UNMAP};

#[no_mangle]
pub extern "C" fn mk_mmio_map(
    device_id: u64,
    claim_epoch: u64,
    bar_index: u32,
    flags: u32,
    offset: u64,
    length: u64,
    out: *mut MmioMapOut,
) -> i64 {
    let bar_flags = ((bar_index as u64) << 32) | (flags as u64 & 0xFFFF_FFFF);
    call_raw(N_MK_MMIO_MAP, [device_id, claim_epoch, bar_flags, offset, length, out as u64])
}

#[no_mangle]
pub extern "C" fn mk_mmio_unmap(grant_id: u64) -> i64 {
    call_raw(N_MK_MMIO_UNMAP, [grant_id, 0, 0, 0, 0, 0])
}
