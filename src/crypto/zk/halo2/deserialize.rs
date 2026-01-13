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
    plonk::VerifyingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::ff::PrimeField;

use crate::crypto::zk::halo2::{
    Halo2Error, MAX_K, MAX_PARAMS_BYTES, MAX_PUBLIC_INPUTS, MAX_VK_BYTES, MIN_K,
};

pub(crate) fn read_params(params_bytes: &[u8]) -> Result<ParamsKZG<Bn256>, Halo2Error> {
    if params_bytes.len() > MAX_PARAMS_BYTES {
        return Err(Halo2Error::SizeLimit("params"));
    }

    if params_bytes.is_empty() {
        return Err(Halo2Error::Deserialize("empty params"));
    }

    let mut cursor = std::io::Cursor::new(params_bytes);

    let params = ParamsKZG::<Bn256>::read(&mut cursor)
        .map_err(|_| Halo2Error::Deserialize("params"))?;

    let k = params.k();
    if k < MIN_K || k > MAX_K {
        return Err(Halo2Error::KOutOfRange);
    }

    Ok(params)
}

pub(crate) fn read_vk(
    params: &ParamsKZG<Bn256>,
    vk_bytes: &[u8],
    format: SerdeFormat,
) -> Result<VerifyingKey<G1Affine>, Halo2Error> {
    if vk_bytes.len() > MAX_VK_BYTES {
        return Err(Halo2Error::SizeLimit("verifying key"));
    }

    if vk_bytes.is_empty() {
        return Err(Halo2Error::Deserialize("empty verifying key"));
    }

    let mut cursor = std::io::Cursor::new(vk_bytes);

    VerifyingKey::<G1Affine>::read::<_, halo2_proofs::plonk::Circuit<Fr>>(
        &mut cursor,
        format,
        params,
    )
    .map_err(|_| Halo2Error::Deserialize("verifying key"))
}

pub(crate) fn parse_public_inputs(columns_le: &[&[[u8; 32]]]) -> Result<Vec<Vec<Fr>>, Halo2Error> {
    let mut total = 0usize;
    let mut out: Vec<Vec<Fr>> = Vec::with_capacity(columns_le.len());
    for col in columns_le {
        let mut v = Vec::with_capacity(col.len());
        for bytes in *col {
            let opt = Fr::from_bytes(bytes);
            if bool::from(opt.is_none()) {
                return Err(Halo2Error::InvalidFieldElement);
            }
            // # SAFETY: We just verified opt.is_some() above via the is_none() check
            if let Some(val) = Option::from(opt) {
                v.push(val);
            } else {
                return Err(Halo2Error::InvalidFieldElement);
            }
        }

        total = total.saturating_add(v.len());
        if total > MAX_PUBLIC_INPUTS {
            return Err(Halo2Error::SizeLimit("public inputs"));
        }

        out.push(v);
    }

    Ok(out)
}
