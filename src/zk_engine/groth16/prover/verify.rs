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

use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::keys::VerifyingKey;
use crate::zk_engine::groth16::pairing::Pairing;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::ZKError;

pub(super) fn verify_proof(
    verifying_key: &VerifyingKey,
    proof: &Proof,
    public_inputs: &[FieldElement],
) -> Result<bool, ZKError> {
    if public_inputs.len() + 1 != verifying_key.ic.len() {
        return Err(ZKError::VerificationFailed);
    }

    let mut vk_x = verifying_key.ic[0].clone();
    for (i, input) in public_inputs.iter().enumerate() {
        let term = verifying_key.ic[i + 1].scalar_mul(&input.limbs);
        vk_x = vk_x.add(&term);
    }

    let pairing1 = Pairing::compute(&proof.a, &proof.b);
    let pairing2 = Pairing::compute(&verifying_key.alpha_g1.neg(), &verifying_key.beta_g2);
    let pairing3 = Pairing::compute(&vk_x.neg(), &verifying_key.gamma_g2);
    let pairing4 = Pairing::compute(&proof.c.neg(), &verifying_key.delta_g2);

    let result = pairing1.mul(&pairing2).mul(&pairing3).mul(&pairing4);

    Ok(result.is_identity())
}
