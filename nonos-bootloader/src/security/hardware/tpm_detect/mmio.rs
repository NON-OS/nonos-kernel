// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const TPM_BASE_ADDR: u64 = 0xFED4_0000;
pub const TPM_DID_VID_OFFSET: u64 = 0xF00;
pub const TPM_RID_OFFSET: u64 = 0xF04;
pub const TPM_INTF_CAP_OFFSET: u64 = 0x14;

pub unsafe fn read_mmio_u32(addr: u64) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

pub unsafe fn read_mmio_u8(addr: u64) -> u8 {
    core::ptr::read_volatile(addr as *const u8)
}
