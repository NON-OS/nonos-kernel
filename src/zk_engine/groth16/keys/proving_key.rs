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

use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::G2Point;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ProvingKey {
    pub alpha_g1: G1Point,
    pub beta_g1: G1Point,
    pub beta_g2: G2Point,
    pub delta_g1: G1Point,
    pub delta_g2: G2Point,
    pub a_query: Vec<G1Point>,
    pub b_g1_query: Vec<G1Point>,
    pub b_g2_query: Vec<G2Point>,
    pub h_query: Vec<G1Point>,
    pub l_query: Vec<G1Point>,
    pub num_variables: usize,
    pub num_inputs: usize,
}
