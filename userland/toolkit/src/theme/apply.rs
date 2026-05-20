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

//! TOOLKIT_OP_THEME_APPLY handler. Payload is five little-endian u32
//! ARGB colour words in fixed order: background, surface, accent,
//! text, border. Replies STATUS_OK on success or E_SHORT if the
//! payload is too small.

use crate::protocol::{E_SHORT, STATUS_OK};

use super::store::{replace, Theme};

pub fn apply(payload: &[u8]) -> u16 {
    if payload.len() < 20 {
        return E_SHORT;
    }
    let new = Theme {
        background_argb: u32_le(&payload[0..4]),
        surface_argb: u32_le(&payload[4..8]),
        accent_argb: u32_le(&payload[8..12]),
        text_argb: u32_le(&payload[12..16]),
        border_argb: u32_le(&payload[16..20]),
        revision: 0,
    };
    replace(new);
    STATUS_OK
}

fn u32_le(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(b);
    u32::from_le_bytes(a)
}
