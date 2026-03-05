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

pub mod groth16;
pub mod circuit;
pub mod setup;
pub mod syscalls;
pub mod verification;
pub mod attestation;

mod types;
mod engine;
mod global;

#[cfg(test)]
mod tests;

pub use types::{ZKConfig, ZKStats, ZKProof, ZKError};
pub use engine::ZKEngine;
pub use global::{
    init_zk_engine, get_zk_engine, get_zk_engine_static,
    compile_circuit, generate_proof, verify_proof,
    generate_groth16_proof, verify_groth16_proof,
    generate_plonk_proof, verify_plonk_proof,
    generate_stark_proof, verify_stark_proof,
    is_zk_engine_initialized,
};
