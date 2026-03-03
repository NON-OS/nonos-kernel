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


use crate::network::onion::OnionError;
use crate::network::onion::cell::CellType;

#[inline]
pub(super) fn now_ms() -> u64 {
    crate::time::now_ns() / 1_000_000
}

#[inline]
pub(super) fn ewma_update(old_ms: u32, sample_ms: u32) -> u32 {
    if old_ms == 0 {
        return sample_ms;
    }
    let alpha_num = 3u32;
    let alpha_den = 10u32;
    (alpha_num * sample_ms + (alpha_den - alpha_num) * old_ms) / alpha_den
}

pub(super) fn strip_len_prefix_if_any(is_var: bool, command: u8, payload: &[u8]) -> Result<&[u8], OnionError> {
    if is_var && (command == CellType::Created2 as u8) {
        if payload.len() < 2 {
            return Err(OnionError::InvalidCell);
        }
        let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + n {
            return Err(OnionError::InvalidCell);
        }
        return Ok(&payload[2..2 + n]);
    }
    if !is_var && command == CellType::Relay as u8 {
        if payload.len() >= 2 {
            let n = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            if payload.len() >= 2 + n && n > 0 && n <= 1024 {
                return Ok(&payload[2..2 + n]);
            }
        }
    }
    Ok(payload)
}
