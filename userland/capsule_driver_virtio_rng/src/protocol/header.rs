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

//! Wire-form header shared by request and response. Identical
//! shape to the entropy/crypto/vfs/ramfs/keyring capsules so the
//! kernel-side client transport can serve them all uniformly.
//!
//!   u32 magic
//!   u16 version
//!   u16 op
//!   u16 flags
//!   u16 _reserved
//!   u32 request_id
//!   u32 payload_len
//! = 20 bytes.

pub const MAGIC: u32 = 0x4E4F_5244; // "NORD" — NONOS Random Driver
pub const VERSION: u16 = 1;

pub const HDR_LEN: usize = 20;
pub const RESP_HDR_LEN: usize = HDR_LEN;

#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub op: u16,
    pub flags: u16,
    pub request_id: u32,
    pub payload_len: u32,
}
