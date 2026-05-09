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

use super::constants::{MAX_METADATA_LEN, NONOS_ID_LEN, PUBLISHER_KEY_ID_LEN};
use super::glob_match::glob_match;
use super::sub::{NamespaceGlob, PublisherKey, TrustAnchorSignature};

#[derive(Debug, Clone)]
pub struct NonosIdCertificate {
    pub schema_version: u16,
    pub cert_serial: u64,
    pub nonos_id: [u8; NONOS_ID_LEN],
    pub namespace_globs: Vec<NamespaceGlob>,
    pub allowed_caps_ceiling: u64,
    pub metadata: [u8; MAX_METADATA_LEN],
    pub metadata_len: u16,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub trust_anchor_epoch: u64,
    pub publisher_keys: Vec<PublisherKey>,
    pub trust_anchor_signatures: Vec<TrustAnchorSignature>,
}

impl NonosIdCertificate {
    pub fn metadata_str(&self) -> &str {
        let n = self.metadata_len as usize;
        core::str::from_utf8(&self.metadata[..n]).unwrap_or("")
    }

    pub fn namespace_matches(&self, namespace: &str) -> bool {
        self.namespace_globs.iter().any(|g| glob_match(g.as_str(), namespace))
    }

    pub fn publisher_key_by_id(
        &self,
        key_id: &[u8; PUBLISHER_KEY_ID_LEN],
    ) -> Option<&PublisherKey> {
        self.publisher_keys.iter().find(|k| &k.key_id == key_id)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifiedNonosId {
    pub nonos_id: [u8; NONOS_ID_LEN],
    pub cert_serial: u64,
    pub allowed_caps_ceiling: u64,
}
