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

pub const OP_OPEN: u16 = 1;
pub const OP_CLOSE: u16 = 2;
pub const OP_READ: u16 = 3;
pub const OP_WRITE: u16 = 4;
pub const OP_TRUNCATE: u16 = 5;

pub const OPEN_FLAG_CREATE: u32 = 0x1;
pub const OPEN_FLAG_TRUNCATE: u32 = 0x2;

pub const KERNEL_REPLY_ENDPOINT: u64 = 0x1_0000_0001;

pub(super) const HDR_LEN: usize = 8;

pub struct Request<'a> {
    pub seq: u32,
    pub op: u16,
    pub payload: &'a [u8],
}
