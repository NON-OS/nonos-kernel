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

use super::g1::serialize_g1;
use super::g2::serialize_g2;
use crate::zk_engine::setup::params::SetupParameters;
use alloc::vec::Vec;

pub(super) fn serialize_params(params: &SetupParameters, out: &mut Vec<u8>) {
    let pk = &params.proving_key;
    out.extend_from_slice(&(pk.num_variables as u32).to_le_bytes());
    out.extend_from_slice(&(pk.num_inputs as u32).to_le_bytes());

    serialize_g1(&pk.alpha_g1, out);
    serialize_g1(&pk.beta_g1, out);
    serialize_g1(&pk.delta_g1, out);
    serialize_g2(&pk.beta_g2, out);
    serialize_g2(&pk.delta_g2, out);

    out.extend_from_slice(&(pk.a_query.len() as u32).to_le_bytes());
    for pt in &pk.a_query {
        serialize_g1(pt, out);
    }

    out.extend_from_slice(&(pk.b_g1_query.len() as u32).to_le_bytes());
    for pt in &pk.b_g1_query {
        serialize_g1(pt, out);
    }

    out.extend_from_slice(&(pk.b_g2_query.len() as u32).to_le_bytes());
    for pt in &pk.b_g2_query {
        serialize_g2(pt, out);
    }

    out.extend_from_slice(&(pk.h_query.len() as u32).to_le_bytes());
    for pt in &pk.h_query {
        serialize_g1(pt, out);
    }

    out.extend_from_slice(&(pk.l_query.len() as u32).to_le_bytes());
    for pt in &pk.l_query {
        serialize_g1(pt, out);
    }

    let vk = &params.verifying_key;
    serialize_g1(&vk.alpha_g1, out);
    serialize_g2(&vk.beta_g2, out);
    serialize_g2(&vk.gamma_g2, out);
    serialize_g2(&vk.delta_g2, out);

    out.extend_from_slice(&(vk.ic.len() as u32).to_le_bytes());
    for pt in &vk.ic {
        serialize_g1(pt, out);
    }
}
