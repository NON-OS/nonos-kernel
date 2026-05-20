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

use crate::input::InputEvent;
use crate::wire::NINP_MAGIC;

pub(super) const NINP_HDR_LEN: usize = 8;
pub(super) const DELIVERY_LEN: usize = NINP_HDR_LEN + 32;

pub(super) fn parse_delivery(buf: &[u8]) -> Option<InputEvent> {
    if buf.len() < DELIVERY_LEN {
        return None;
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    if magic != NINP_MAGIC {
        return None;
    }
    InputEvent::from_delivery(&buf[NINP_HDR_LEN..])
}
