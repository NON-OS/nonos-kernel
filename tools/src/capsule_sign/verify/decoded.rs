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

pub struct DecodedTaKey {
    pub alg: AlgId,
    pub pubkey: Vec<u8>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

pub struct DecodedTaPolicy {
    pub epoch: u64,
    pub keys: Vec<DecodedTaKey>,
    pub revoked_cert_serials: Vec<u64>,
    pub revoked_nonos_ids: Vec<[u8; 32]>,
    pub revoked_publisher_key_ids: Vec<[u8; 16]>,
    pub flags: u32,
}

pub struct DecodedPubKey {
    pub alg: AlgId,
    pub key_id: [u8; 16],
    pub pubkey: Vec<u8>,
}

pub struct DecodedTaSig {
    pub alg: AlgId,
    pub sig: Vec<u8>,
}

pub struct DecodedCert {
    pub cert_serial: u64,
    pub nonos_id: [u8; 32],
    pub namespace_globs: Vec<String>,
    pub allowed_caps_ceiling: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub trust_anchor_epoch: u64,
    pub publisher_keys: Vec<DecodedPubKey>,
    pub trust_anchor_signatures: Vec<DecodedTaSig>,
    pub signed_region_len: usize,
}

pub struct DecodedEndpoint {
    pub kind: u8,
    pub port: u32,
    pub name: String,
}

pub struct DecodedPubSig {
    pub alg: AlgId,
    pub key_id: [u8; 16],
    pub sig: Vec<u8>,
}

pub struct DecodedManifest {
    pub nonos_id_cert_id: [u8; 32],
    pub namespace: String,
    pub version_major: u32,
    pub target_triple: String,
    pub payload_hash: [u8; 32],
    pub required_caps: u64,
    pub optional_caps: u64,
    pub endpoints: Vec<DecodedEndpoint>,
    pub publisher_signatures: Vec<DecodedPubSig>,
    pub signed_region_len: usize,
}
