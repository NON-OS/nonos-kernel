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

//! `net.ip` v1 envelope. UDP talks to the IP capsule with the
//! same 20-byte v1 header every userland service uses; the
//! distinguishing field is `MAGIC = "NIP4"`.

pub const IP_MAGIC: u32 = 0x4E49_5034; // "NIP4"
pub const IP_VERSION: u16 = 1;
pub const IP_HDR_LEN: usize = 20;

pub const OP_GET_CONFIG: u16 = 2;
pub const OP_SEND_PACKET: u16 = 4;
pub const OP_POLL_PACKET: u16 = 5;

pub const IP_PROTO_UDP: u8 = 17;
