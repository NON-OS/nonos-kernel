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

//! Legacy 8254x descriptor layout. Both RX and TX descriptors are
//! 16 bytes; the device-side fields are written by the NIC, the
//! driver-side fields by this capsule. `repr(C)` plus a const
//! size-assert keeps the wire layout honest under any future
//! field reorder.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);
const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);
