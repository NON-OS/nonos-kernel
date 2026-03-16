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
use super::super::types::{TLS_1_2, TLS_1_3};

pub fn parse_server_hello(body: &[u8]) -> Result<(u16, [u8; 32], [u8; 32]), OnionError> {
    if body.len() < 40 { return Err(OnionError::InvalidCell); }
    let mut off = 0usize;
    if u16::from_be_bytes([body[off], body[off + 1]]) != TLS_1_2 { return Err(OnionError::CryptoError); }
    off += 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[off..off + 32]);
    off += 32;
    off += 1 + body[off] as usize;
    let suite = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 3;
    let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ext_len { return Err(OnionError::InvalidCell); }
    let mut exts = &body[off..off + ext_len];
    let mut server_pub = [0u8; 32];
    let (mut seen_sv, mut seen_ks) = (false, false);
    while exts.len() >= 4 {
        let ety = u16::from_be_bytes([exts[0], exts[1]]);
        let el = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        if exts.len() < 4 + el { return Err(OnionError::InvalidCell); }
        let eb = &exts[4..4 + el];
        match ety {
            0x002b => { if el != 2 || u16::from_be_bytes([eb[0], eb[1]]) != TLS_1_3 { return Err(OnionError::CryptoError); } seen_sv = true; }
            0x0033 => { if el < 36 { return Err(OnionError::CryptoError); } server_pub.copy_from_slice(&eb[4..36]); seen_ks = true; }
            _ => {}
        }
        exts = &exts[4 + el..];
    }
    if !(seen_sv && seen_ks) { return Err(OnionError::CryptoError); }
    Ok((suite, server_pub, random))
}

pub fn has_tls12_downgrade_sentinel(random: &[u8; 32]) -> bool {
    &random[24..32] == &[0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
}
