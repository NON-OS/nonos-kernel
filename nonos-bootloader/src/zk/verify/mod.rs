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

mod constants;
mod types;
mod verify;

#[cfg(feature = "zk-groth16")]
mod groth16;

#[cfg(feature = "zk-groth16")]
pub use constants::GROTH16_PROOF_LEN;
pub use constants::{DS_PROGRAM_HASH, MAX_INPUT_SIZE, MAX_PROOF_SIZE};

pub use types::{ZkProof, ZkVerifyResult};
pub use verify::{ct_eq32, derive_program_hash, verify_proof};

#[cfg(feature = "zk-groth16")]
pub use groth16::{groth16_verify, GrothErr};
