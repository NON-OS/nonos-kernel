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

pub struct TrustAnchorKeyInput {
    pub alg: AlgId,
    pub pubkey: Vec<u8>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

pub struct TrustAnchorPolicyInput {
    pub epoch: u64,
    pub keys: Vec<TrustAnchorKeyInput>,
    pub revoked_cert_serials: Vec<u64>,
    pub revoked_nonos_ids: Vec<[u8; 32]>,
    pub revoked_publisher_key_ids: Vec<[u8; 16]>,
    pub flags: u32,
}
