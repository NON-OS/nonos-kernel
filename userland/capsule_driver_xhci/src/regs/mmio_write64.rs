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

//! Volatile 64-bit MMIO write. Used for CRCR / DCBAAP / ERSTBA /
//! ERDP — registers that must be programmed atomically as a
//! single 64-bit transaction. See `mmio_read64` for the
//! AC64 prerequisite.

pub(crate) fn mmio_write64(addr: u64, value: u64) {
    unsafe { core::ptr::write_volatile(addr as *mut u64, value) };
}
