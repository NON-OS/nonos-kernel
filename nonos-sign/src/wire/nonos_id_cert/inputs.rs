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

pub struct PublisherKeyInput {
    pub alg: AlgId,
    pub key_id: [u8; 16],
    pub pubkey: Vec<u8>,
}

pub struct TrustAnchorSignatureInput {
    pub alg: AlgId,
    pub sig: Vec<u8>,
}

pub struct NonosIdCertInputs {
    pub cert_serial: u64,
    pub nonos_id: [u8; 32],
    pub namespace_globs: Vec<String>,
    pub allowed_caps_ceiling: u64,
    pub metadata: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub trust_anchor_epoch: u64,
    pub publisher_keys: Vec<PublisherKeyInput>,
}
