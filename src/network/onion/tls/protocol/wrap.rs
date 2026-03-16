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

pub fn wrap_handshake(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(typ);
    hs.push(((body.len() >> 16) & 0xFF) as u8);
    hs.push(((body.len() >> 8) & 0xFF) as u8);
    hs.push((body.len() & 0xFF) as u8);
    hs.extend_from_slice(body);
    hs
}

pub fn wrap_record(ct: u8, legacy_version: u16, body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + body.len());
    rec.push(ct);
    rec.extend_from_slice(&legacy_version.to_be_bytes());
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}
