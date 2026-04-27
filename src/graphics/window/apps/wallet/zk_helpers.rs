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

extern crate alloc;
use crate::crypto::blake3_hash;

pub(super) fn generate_blinding_factor() -> [u8; 32] {
    use crate::interrupts::timer::tick_count;
    let t = tick_count();
    let seed = [
        (t >> 56) as u8,
        (t >> 48) as u8,
        (t >> 40) as u8,
        (t >> 32) as u8,
        (t >> 24) as u8,
        (t >> 16) as u8,
        (t >> 8) as u8,
        t as u8,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
        0xCA,
        0xFE,
        0xBA,
        0xBE,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9A,
        0xBC,
        0xDE,
        0xF0,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
    ];
    blake3_hash(&seed)
}

pub(super) fn compute_balance_commitment(bal: u128, blind: &[u8; 32]) -> [u8; 32] {
    let mut i = [0u8; 48];
    i[..16].copy_from_slice(&bal.to_le_bytes());
    i[16..48].copy_from_slice(blind);
    blake3_hash(&i)
}

pub(super) fn compute_spend_pubkey_commitment(ss: &[u8; 32]) -> [u8; 32] {
    blake3_hash(&[b"NONOS:STEALTH:SPEND:", ss.as_slice()].concat())
}

pub(super) fn bytes_to_field_input(b: &[u8]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let l = b.len().min(32);
    r[..l].copy_from_slice(&b[..l]);
    r
}
