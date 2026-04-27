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

use crate::zk_engine::groth16::{G1Point, G2Point};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Powers {
    pub tau_g1: Vec<G1Point>,
    pub tau_g2: Vec<G2Point>,
    pub alpha_tau_g1: Vec<G1Point>,
    pub beta_tau_g1: Vec<G1Point>,
    pub beta_g2: G2Point,
}
