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

use crate::crypto::asymmetric::alg_id::AlgId;
use crate::crypto::hash::blake3::Hasher;

use super::schema::{NONOS_ID_LEN, PUBLISHER_KEY_ID_LEN};

const NONOS_ID_DOMAIN: &[u8] = b"nonos.id.v1";

// nonos_id stays stable across cert renewals: derived only from
// canonical publisher identity (handle, domain, optional recovery).
pub fn derive_nonos_id(handle: &[u8], domain: &[u8], recovery: &[u8]) -> [u8; NONOS_ID_LEN] {
    assert!(handle.len() <= u8::MAX as usize, "handle too long");
    assert!(domain.len() <= u8::MAX as usize, "domain too long");
    assert!(recovery.len() <= u8::MAX as usize, "recovery too long");
    let mut hasher = Hasher::new();
    hasher.update(NONOS_ID_DOMAIN);
    hasher.update(&[handle.len() as u8]);
    hasher.update(handle);
    hasher.update(&[domain.len() as u8]);
    hasher.update(domain);
    hasher.update(&[recovery.len() as u8]);
    hasher.update(recovery);
    hasher.finalize()
}

pub fn derive_publisher_key_id(alg: AlgId, pubkey: &[u8]) -> [u8; PUBLISHER_KEY_ID_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(&[alg.as_u8()]);
    hasher.update(pubkey);
    let mut out = [0u8; PUBLISHER_KEY_ID_LEN];
    out.copy_from_slice(&hasher.finalize()[..PUBLISHER_KEY_ID_LEN]);
    out
}
