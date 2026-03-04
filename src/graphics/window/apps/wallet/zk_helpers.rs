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

use alloc::vec::Vec;
use crate::crypto::blake3_hash;
use super::types::ADDRESS_LEN;

pub(super) fn generate_blinding_factor() -> [u8; 32] {
    use crate::interrupts::timer::tick_count;
    let ticks = tick_count();
    let seed = [
        (ticks >> 56) as u8,
        (ticks >> 48) as u8,
        (ticks >> 40) as u8,
        (ticks >> 32) as u8,
        (ticks >> 24) as u8,
        (ticks >> 16) as u8,
        (ticks >> 8) as u8,
        ticks as u8,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    blake3_hash(&seed)
}

pub(super) fn compute_balance_commitment(balance: u128, blinding: &[u8; 32]) -> [u8; 32] {
    let balance_bytes = balance.to_le_bytes();
    let mut input = [0u8; 48];
    input[..16].copy_from_slice(&balance_bytes);
    input[16..48].copy_from_slice(blinding);
    blake3_hash(&input)
}

pub(super) fn compute_amount_commitment(amount: u128, nonce: &[u8; 32]) -> [u8; 32] {
    let amount_bytes = amount.to_le_bytes();
    let mut input = [0u8; 48];
    input[..16].copy_from_slice(&amount_bytes);
    input[16..48].copy_from_slice(nonce);
    blake3_hash(&input)
}

pub(super) fn compute_tx_hash(
    sender: &[u8; ADDRESS_LEN],
    recipient: &[u8; ADDRESS_LEN],
    amount_commitment: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(104);
    input.extend_from_slice(sender);
    input.extend_from_slice(recipient);
    input.extend_from_slice(amount_commitment);
    input.extend_from_slice(nonce);
    blake3_hash(&input)
}

pub(super) fn compute_spend_pubkey_commitment(spend_secret: &[u8; 32]) -> [u8; 32] {
    blake3_hash(&[b"NONOS:STEALTH:SPEND:", spend_secret.as_slice()].concat())
}

pub(super) fn bytes_to_field_input(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}
