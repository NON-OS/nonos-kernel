// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::generated::Announcement;
use super::keypair::StealthKeyPair;
use super::scalar::{normalize_scalar, scalar_add};
use super::utils::pubkey_to_address;
use crate::crypto::asymmetric::secp256k1::{multiply_point, public_key_from_secret, SecretKey};
use crate::crypto::hash::keccak256;
use alloc::vec::Vec;

pub fn scan_announcements(
    keys: &StealthKeyPair,
    announcements: &[Announcement],
) -> Vec<(usize, SecretKey, [u8; 20])> {
    let mut found = Vec::new();
    for (idx, announcement) in announcements.iter().enumerate() {
        let shared_secret = match multiply_point(&announcement.ephemeral_pubkey, keys.viewing_key())
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut hash_input = Vec::with_capacity(65);
        hash_input.extend_from_slice(&shared_secret);
        let hashed_secret = normalize_scalar(keccak256(&hash_input));
        if hashed_secret[0] != announcement.view_tag {
            continue;
        }
        let stealth_private_key = match scalar_add(keys.spending_key(), &hashed_secret) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let stealth_pubkey = match public_key_from_secret(&stealth_private_key) {
            Some(pk) => pk,
            None => continue,
        };
        let derived_address = pubkey_to_address(&stealth_pubkey);
        if derived_address == announcement.stealth_address {
            found.push((idx, stealth_private_key, derived_address));
        }
    }
    found
}

pub fn compute_view_tag(shared_secret: &[u8; 65]) -> u8 {
    keccak256(shared_secret)[0]
}
