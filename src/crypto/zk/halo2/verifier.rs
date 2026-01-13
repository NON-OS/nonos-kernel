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

use alloc::vec::Vec;

use halo2_proofs::{
    plonk::{self, VerifyingKey},
    poly::kzg::{
        commitment::ParamsKZG,
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

use crate::crypto::zk::halo2::{
    deserialize::{parse_public_inputs, read_params, read_vk},
    Halo2Error, MAX_PROOF_BYTES,
};

pub struct Halo2Verifier {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
    num_instance_columns: usize,
}

impl Halo2Verifier {
    #[must_use = "verifier should be used for verification"]
    pub fn new(
        params_bytes: &[u8],
        vk_bytes: &[u8],
        format: SerdeFormat,
    ) -> Result<Self, Halo2Error> {
        let params = read_params(params_bytes)?;
        let vk = read_vk(&params, vk_bytes, format)?;
        let num_instance_columns = vk.cs().num_instance_columns();

        Ok(Self {
            params,
            vk,
            num_instance_columns,
        })
    }

    #[must_use = "verifier should be used for verification"]
    pub fn from_bytes(params_bytes: &[u8], vk_bytes: &[u8]) -> Result<Self, Halo2Error> {
        Self::new(params_bytes, vk_bytes, SerdeFormat::RawBytes)
    }

    #[inline]
    #[must_use]
    pub fn k(&self) -> u32 {
        self.params.k()
    }

    #[inline]
    #[must_use]
    pub fn n(&self) -> u64 {
        self.params.n()
    }

    #[inline]
    #[must_use]
    pub fn num_instance_columns(&self) -> usize {
        self.num_instance_columns
    }

    #[must_use = "verification result must be checked"]
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        instances: &[&[[u8; 32]]],
    ) -> Result<(), Halo2Error> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(Halo2Error::SizeLimit("proof"));
        }

        if proof_bytes.is_empty() {
            return Err(Halo2Error::Deserialize("empty proof"));
        }

        if instances.len() != self.num_instance_columns {
            return Err(Halo2Error::PublicInputShape);
        }

        let instance_values = parse_public_inputs(instances)?;

        let instance_refs: Vec<&[Fr]> = instance_values
            .iter()
            .map(|col| col.as_slice())
            .collect();

        let instances_slice: &[&[Fr]] = &instance_refs;

        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes);

        let strategy = SingleStrategy::new(&self.params);

        plonk::verify_proof::<_, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &self.params,
            &self.vk,
            strategy,
            &[instances_slice],
            &mut transcript,
        )
        .map_err(|_| Halo2Error::VerifyFailed)?;

        Ok(())
    }

    #[must_use = "verification result must be checked"]
    pub fn verify_batch(
        &self,
        proofs: &[&[u8]],
        instances_list: &[&[&[[u8; 32]]]],
    ) -> Result<(), Halo2Error> {
        if proofs.len() != instances_list.len() {
            return Err(Halo2Error::PublicInputShape);
        }

        for (proof_bytes, instances) in proofs.iter().zip(instances_list.iter()) {
            self.verify(proof_bytes, instances)?;
        }

        Ok(())
    }
}
