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

mod circuit_api;
mod groth16;
mod plonk;
mod stark;
mod state;

pub use circuit_api::{compile_circuit, generate_proof, verify_proof};
pub use groth16::{generate_groth16_proof, verify_groth16_proof};
pub use plonk::{generate_plonk_proof, verify_plonk_proof};
pub use stark::{generate_stark_proof, verify_stark_proof};
pub use state::{get_zk_engine, get_zk_engine_static, init_zk_engine, is_zk_engine_initialized};
