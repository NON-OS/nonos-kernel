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

//! Port-IO grant + access wrappers. Cap requirement: `Pio`. The
//! kernel is the only side that ever executes `in`/`out`; userland
//! drives every read and write through these wrappers, which trap
//! into the kernel mediator.

use super::types::PioGrantOut;
use crate::syscall::{
    call_raw, N_MK_PIO_GRANT, N_MK_PIO_READ, N_MK_PIO_RELEASE, N_MK_PIO_WRITE,
};

#[no_mangle]
pub extern "C" fn mk_pio_grant(
    device_id: u64,
    claim_epoch: u64,
    bar_index: u8,
    flags: u32,
    out: *mut PioGrantOut,
) -> i64 {
    call_raw(
        N_MK_PIO_GRANT,
        [device_id, claim_epoch, bar_index as u64, flags as u64, out as u64, 0],
    )
}

#[no_mangle]
pub extern "C" fn mk_pio_read(
    grant_id: u64,
    port_offset: u16,
    width: u8,
    out_value: *mut u32,
) -> i64 {
    call_raw(
        N_MK_PIO_READ,
        [grant_id, port_offset as u64, width as u64, out_value as u64, 0, 0],
    )
}

#[no_mangle]
pub extern "C" fn mk_pio_write(
    grant_id: u64,
    port_offset: u16,
    width: u8,
    value: u32,
) -> i64 {
    call_raw(
        N_MK_PIO_WRITE,
        [grant_id, port_offset as u64, width as u64, value as u64, 0, 0],
    )
}

#[no_mangle]
pub extern "C" fn mk_pio_release(grant_id: u64) -> i64 {
    call_raw(N_MK_PIO_RELEASE, [grant_id, 0, 0, 0, 0, 0])
}
