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

use alloc::vec::Vec;

use super::super::super::protocol::AEAD_HEADER_BYTES;

pub(super) fn build(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(AEAD_HEADER_BYTES as usize + aad.len() + payload.len());
    frame.extend_from_slice(key);
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&(aad.len() as u32).to_le_bytes());
    frame.extend_from_slice(aad);
    frame.extend_from_slice(payload);
    frame
}
