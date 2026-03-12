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

pub const TPM_MMIO_BASE: u64 = 0xFED4_0000;
pub const TPM_MMIO_SIZE: usize = 0x5000;

pub const TPM_ACCESS: u32 = 0x0000;
pub const TPM_STS: u32 = 0x0018;
pub const TPM_DATA_FIFO: u32 = 0x0024;
pub const TPM_INTERFACE_ID: u32 = 0x0030;
pub const TPM_DID_VID: u32 = 0x0F00;

pub const TPM_ACCESS_VALID: u8 = 0x80;
pub const TPM_ACCESS_ACTIVE: u8 = 0x20;
pub const TPM_ACCESS_REQUEST: u8 = 0x02;

pub const TPM_STS_VALID: u8 = 0x80;
pub const TPM_STS_READY: u8 = 0x40;
pub const TPM_STS_GO: u8 = 0x20;
pub const TPM_STS_DATA_AVAIL: u8 = 0x10;
pub const TPM_STS_DATA_EXPECT: u8 = 0x08;
