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

use super::g1::{deserialize_g1, deserialize_g1_vec};
use super::g2::deserialize_g2;
use super::g2_vec::deserialize_g2_vec;
use crate::zk_engine::groth16::{ProvingKey, VerifyingKey};
use crate::zk_engine::setup::params::SetupParameters;
use crate::zk_engine::ZKError;

pub(super) fn deserialize_params(data: &[u8]) -> Result<SetupParameters, ZKError> {
    if data.len() < 8 {
        return Err(ZKError::InvalidFormat);
    }

    let mut offset = 0;

    let num_variables =
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    offset += 4;
    let num_inputs =
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
            as usize;
    offset += 4;

    let (alpha_g1, o) = deserialize_g1(data, offset)?;
    offset = o;
    let (beta_g1, o) = deserialize_g1(data, offset)?;
    offset = o;
    let (delta_g1, o) = deserialize_g1(data, offset)?;
    offset = o;
    let (beta_g2, o) = deserialize_g2(data, offset)?;
    offset = o;
    let (delta_g2, o) = deserialize_g2(data, offset)?;
    offset = o;

    let (a_query, o) = deserialize_g1_vec(data, offset)?;
    offset = o;
    let (b_g1_query, o) = deserialize_g1_vec(data, offset)?;
    offset = o;
    let (b_g2_query, o) = deserialize_g2_vec(data, offset)?;
    offset = o;
    let (h_query, o) = deserialize_g1_vec(data, offset)?;
    offset = o;
    let (l_query, o) = deserialize_g1_vec(data, offset)?;
    offset = o;

    let proving_key = ProvingKey {
        alpha_g1,
        beta_g1,
        beta_g2,
        delta_g1,
        delta_g2,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
        num_variables,
        num_inputs,
    };

    let (vk_alpha_g1, o) = deserialize_g1(data, offset)?;
    offset = o;
    let (vk_beta_g2, o) = deserialize_g2(data, offset)?;
    offset = o;
    let (vk_gamma_g2, o) = deserialize_g2(data, offset)?;
    offset = o;
    let (vk_delta_g2, o) = deserialize_g2(data, offset)?;
    offset = o;
    let (ic, _) = deserialize_g1_vec(data, offset)?;

    let verifying_key = VerifyingKey {
        alpha_g1: vk_alpha_g1,
        beta_g2: vk_beta_g2,
        gamma_g2: vk_gamma_g2,
        delta_g2: vk_delta_g2,
        ic,
    };

    Ok(SetupParameters { proving_key, verifying_key, toxic_waste: None })
}
