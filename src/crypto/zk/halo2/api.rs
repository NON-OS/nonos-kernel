// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use halo2_proofs::SerdeFormat;

use crate::crypto::zk::halo2::{verifier::Halo2Verifier, Halo2Error};

#[must_use = "verification result must be checked"]
pub fn halo2_verify(
    params_bytes: &[u8],
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    instances: &[&[[u8; 32]]],
) -> Result<(), Halo2Error> {
    let verifier = Halo2Verifier::from_bytes(params_bytes, vk_bytes)?;
    verifier.verify(proof_bytes, instances)
}

#[must_use = "verification result must be checked"]
pub fn halo2_verify_with_format(
    params_bytes: &[u8],
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    instances: &[&[[u8; 32]]],
    format: SerdeFormat,
) -> Result<(), Halo2Error> {
    let verifier = Halo2Verifier::new(params_bytes, vk_bytes, format)?;
    verifier.verify(proof_bytes, instances)
}
