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

use nonos_libc::InputEvent;

// Outbound delivery envelope sent to subscribers (separate magic
// from the request channel so subscribers cannot accidentally
// reply on the wrong header). Layout: 4-byte magic NINP + 2-byte
// version + 2-byte flags + 32-byte InputEvent payload.
pub const DELIVERY_MAGIC: u32 = 0x4E49_4E50; // "NINP"
pub const DELIVERY_VERSION: u16 = 1;
const HDR_LEN: usize = 8;
const EVENT_LEN: usize = core::mem::size_of::<InputEvent>();
pub const DELIVERY_LEN: usize = HDR_LEN + EVENT_LEN;

pub fn encode_delivery(out: &mut [u8; DELIVERY_LEN], event: &InputEvent) {
    out[0..4].copy_from_slice(&DELIVERY_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&DELIVERY_VERSION.to_le_bytes());
    out[6..8].fill(0);
    out[8..10].copy_from_slice(&event.kind.to_le_bytes());
    out[10..12].copy_from_slice(&event.flags.to_le_bytes());
    out[12..16].copy_from_slice(&event.code.to_le_bytes());
    out[16..20].copy_from_slice(&event.x.to_le_bytes());
    out[20..24].copy_from_slice(&event.y.to_le_bytes());
    out[24..28].copy_from_slice(&event.delta_x.to_le_bytes());
    out[28..32].copy_from_slice(&event.delta_y.to_le_bytes());
    out[32..40].copy_from_slice(&event.timestamp_ns.to_le_bytes());
}
