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

use super::constants::{
    MAX_NAMESPACE_LEN, MAX_TARGET_TRIPLE_LEN, NONOS_ID_CERT_ID_LEN, PAYLOAD_HASH_LEN,
};
use super::endpoint::EndpointDecl;
use super::publisher_sig::PublisherSignature;
use super::version::Version;

#[derive(Debug, Clone)]
pub struct CapsuleManifest {
    pub schema_version: u16,
    pub nonos_id_cert_id: [u8; NONOS_ID_CERT_ID_LEN],
    pub namespace: [u8; MAX_NAMESPACE_LEN],
    pub namespace_len: u8,
    pub version: Version,
    pub target_triple: [u8; MAX_TARGET_TRIPLE_LEN],
    pub target_triple_len: u8,
    pub payload_hash: [u8; PAYLOAD_HASH_LEN],
    pub required_caps: u64,
    pub optional_caps: u64,
    pub endpoints: Vec<EndpointDecl>,
    pub publisher_signatures: Vec<PublisherSignature>,
}

impl CapsuleManifest {
    pub fn namespace_str(&self) -> &str {
        let n = self.namespace_len as usize;
        core::str::from_utf8(&self.namespace[..n]).unwrap_or("")
    }

    pub fn target_triple_str(&self) -> &str {
        let n = self.target_triple_len as usize;
        core::str::from_utf8(&self.target_triple[..n]).unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    pub manifest: CapsuleManifest,
    pub capsule_id: [u8; 32],
}
