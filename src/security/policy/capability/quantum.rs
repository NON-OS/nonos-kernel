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

use core::sync::atomic::AtomicU64;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct QuantumState {
    pub entangled_particles: Vec<QuantumParticle>,
    pub decoherence_timer: AtomicU64,
    pub quantum_key: [u8; 64],
}

#[derive(Debug)]
pub struct QuantumParticle {
    pub state_vector: [f64; 4],
    pub spin: f64,
    pub position_uncertainty: f64,
    pub momentum_uncertainty: f64,
    pub last_measurement: u64,
}
