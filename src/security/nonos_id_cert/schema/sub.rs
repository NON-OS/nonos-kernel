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

use crate::crypto::asymmetric::alg_id::{AlgId, MAX_PUBKEY_BYTES, MAX_SIG_BYTES};

use super::constants::{MAX_NAMESPACE_GLOB_LEN, PUBLISHER_KEY_ID_LEN};

#[derive(Debug, Clone)]
pub struct NamespaceGlob {
    pub bytes: [u8; MAX_NAMESPACE_GLOB_LEN],
    pub len: u8,
}

impl NamespaceGlob {
    pub fn as_str(&self) -> &str {
        let n = self.len as usize;
        core::str::from_utf8(&self.bytes[..n]).unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct PublisherKey {
    pub algorithm: AlgId,
    pub key_id: [u8; PUBLISHER_KEY_ID_LEN],
    pub pubkey: [u8; MAX_PUBKEY_BYTES],
    pub pubkey_len: u16,
}

impl PublisherKey {
    pub fn pubkey_bytes(&self) -> &[u8] {
        &self.pubkey[..self.pubkey_len as usize]
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchorSignature {
    pub algorithm: AlgId,
    pub sig: [u8; MAX_SIG_BYTES],
    pub sig_len: u16,
}

impl TrustAnchorSignature {
    pub fn sig_bytes(&self) -> &[u8] {
        &self.sig[..self.sig_len as usize]
    }
}
