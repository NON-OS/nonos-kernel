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

// Outbound lifecycle notification envelope. Separate magic so a
// subscriber cannot accidentally reply over the request channel.
// Layout: 4-byte NWMV + 2-byte version + 2-byte flags + 20-byte body.

pub const NOTIFY_MAGIC: u32 = 0x4E57_4D56; // "NWMV"
pub const NOTIFY_VERSION: u16 = 1;
const HDR_LEN: usize = 8;
const BODY_LEN: usize = 20;
pub const NOTIFY_LEN: usize = HDR_LEN + BODY_LEN;

pub const NOTIFY_KIND_OPENED: u32 = 0;
pub const NOTIFY_KIND_CLOSED: u32 = 1;

pub fn encode_notify(
    out: &mut [u8; NOTIFY_LEN],
    event_kind: u32,
    owner_pid: u32,
    window_id: u32,
    x: u32,
    y: u32,
) {
    out[0..4].copy_from_slice(&NOTIFY_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&NOTIFY_VERSION.to_le_bytes());
    out[6..8].fill(0);
    out[8..12].copy_from_slice(&event_kind.to_le_bytes());
    out[12..16].copy_from_slice(&owner_pid.to_le_bytes());
    out[16..20].copy_from_slice(&window_id.to_le_bytes());
    out[20..24].copy_from_slice(&x.to_le_bytes());
    out[24..28].copy_from_slice(&y.to_le_bytes());
}
