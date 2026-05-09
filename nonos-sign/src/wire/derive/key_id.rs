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

use crate::algs::AlgId;
use crate::wire::constants::PUBLISHER_KEY_ID_LEN;

pub fn derive_publisher_key_id(alg: AlgId, pubkey: &[u8]) -> [u8; PUBLISHER_KEY_ID_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(&[alg as u8]);
    h.update(pubkey);
    let full = *h.finalize().as_bytes();
    let mut out = [0u8; PUBLISHER_KEY_ID_LEN];
    out.copy_from_slice(&full[..PUBLISHER_KEY_ID_LEN]);
    out
}
