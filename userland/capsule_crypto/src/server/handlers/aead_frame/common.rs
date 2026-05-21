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

use super::constants::{HEADER_LEN, KEY_LEN, MAX_AAD, NONCE_LEN};
use super::types::{CommonParts, FrameError};

pub(crate) fn parse_common(payload: &[u8]) -> Result<CommonParts<'_>, FrameError> {
    let key = payload.get(0..KEY_LEN).ok_or(FrameError::Short)?;
    let nonce = payload.get(KEY_LEN..KEY_LEN + NONCE_LEN).ok_or(FrameError::Short)?;
    let aad_len_bytes = payload.get(KEY_LEN + NONCE_LEN..HEADER_LEN).ok_or(FrameError::Short)?;
    let aad_len = u32::from_le_bytes([
        aad_len_bytes[0],
        aad_len_bytes[1],
        aad_len_bytes[2],
        aad_len_bytes[3],
    ]) as usize;
    if aad_len > MAX_AAD {
        return Err(FrameError::OversizeAad);
    }
    let aad_end = HEADER_LEN.checked_add(aad_len).ok_or(FrameError::OversizeAad)?;
    let aad = payload.get(HEADER_LEN..aad_end).ok_or(FrameError::Short)?;
    let body = payload.get(aad_end..).ok_or(FrameError::Short)?;
    Ok(CommonParts { key, nonce, aad, body })
}
