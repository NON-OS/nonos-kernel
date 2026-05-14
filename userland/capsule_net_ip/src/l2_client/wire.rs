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

//! `net.l2` v1 envelope, as the IP capsule sees it. The L2 capsule
//! reads `mk_ipc_recv_from` and replies via `mk_ipc_send_to_pid`,
//! so the wire layout is the standard 20-byte v1 header on both
//! request and response. The IP capsule's reply lands on its own
//! per-process inbox; no envelope reply_port field is needed.

pub const L2_MAGIC: u32 = 0x4E4C_3200; // "NL2\0"
pub const L2_VERSION: u16 = 1;
pub const L2_HDR_LEN: usize = 20;

pub const OP_GET_MAC: u16 = 2;
pub const OP_GET_LINK: u16 = 3;
pub const OP_SEND_FRAME: u16 = 4;
pub const OP_POLL_FRAME: u16 = 5;
pub const OP_ARP_RESOLVE: u16 = 6;
