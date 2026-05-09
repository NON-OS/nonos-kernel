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

#[derive(Debug, Clone, Copy)]
pub struct SignaturePolicy<'a> {
    pub required: &'a [AlgId],
}

impl<'a> SignaturePolicy<'a> {
    pub fn requires(&self, alg: AlgId) -> bool {
        self.required.iter().any(|&a| a == alg)
    }
}

// nonos-production policy: hybrid Ed25519 + ML-DSA-65, both required.
pub const NONOS_PRODUCTION_POLICY: SignaturePolicy<'static> =
    SignaturePolicy { required: &[AlgId::Ed25519, AlgId::MlDsa65] };
