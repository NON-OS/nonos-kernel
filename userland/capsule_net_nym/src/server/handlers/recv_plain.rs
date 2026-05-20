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

use crate::protocol::MIX_PAYLOAD_MAX;
use crate::state::Session;

pub fn queue(s: &mut Session, plain: &[u8]) {
    if plain.len() < 2 {
        return;
    }
    let len = u16::from_le_bytes([plain[0], plain[1]]) as usize;
    if len > MIX_PAYLOAD_MAX || 2 + len > plain.len() {
        return;
    }
    let mut body = Vec::with_capacity(len);
    body.extend_from_slice(&plain[2..2 + len]);
    s.push(body);
}
