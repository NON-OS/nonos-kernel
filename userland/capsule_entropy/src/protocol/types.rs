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

// Wire format. Authoritative; the kernel-side mirror at
// `src/security/entropy_capsule/protocol.rs` must match bit-for-bit.
//
// Request and response share a fixed header. The header carries
// `magic + version` so a stale or wrong-protocol envelope is rejected
// with EINVAL before any handler runs. `request_id` is echoed in the
// response so the caller can match replies; the capsule never reads
// it for routing — IPC handles routing through the per-process inbox.

pub const MAGIC: u32 = 0x4E4F_454E; // "NOEN" — NONOS Entropy
pub const VERSION: u16 = 1;

// Op discriminants. Unknown op → EINVAL.
pub const OP_GET_RANDOM: u16 = 1;
pub const OP_GET_STATS: u16 = 2;
pub const OP_RESEED: u16 = 3;
pub const OP_HEALTHCHECK: u16 = 4;

// Bounded sizes.
pub const MAX_RANDOM_BYTES: u32 = 4096;
pub const MAX_RESEED_BYTES: u32 = 256;
pub const MAX_PAYLOAD_BYTES: u32 = 4096;

// Inbox name shape: "endpoint.<u64>". The kernel client owns this
// reply inbox (registered with pid=0); ownership-checked at recv.
pub const KERNEL_REPLY_ENDPOINT: u64 = 0x1_0000_0003;

// Header layout, little-endian, packed:
//   u32 magic
//   u16 version
//   u16 op
//   u16 flags
//   u16 _reserved
//   u32 request_id
//   u32 payload_len
// = 20 bytes. Request and response share this layout; response also
// carries i32 status in the first 4 bytes of its payload.
pub const HDR_LEN: usize = 20;

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub op: u16,
    pub flags: u16,
    pub request_id: u32,
    pub payload: &'a [u8],
}
