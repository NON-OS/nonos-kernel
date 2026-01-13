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

extern crate alloc;

mod constants;
mod field;
mod utils;
mod pedersen;
mod schnorr;
mod sigma;
mod range;
mod equality;
mod membership;
mod plonk;
mod verifier;
mod syscall;
#[cfg(test)]
mod tests;

// Re-export constants
pub use constants::{
    DOM_SCHNORR, DOM_PEDERSEN, DOM_RANGE, DOM_EQUALITY,
    DOM_MERKLE, DOM_SIGMA, DOM_PLONK, L,
};

// Re-export field element
pub use field::FieldElement;
// Re-export utility functions
pub use utils::{zeroize, constant_time_eq};
// Re-export proof types
pub use pedersen::PedersenCommitment;
pub use schnorr::SchnorrProof;
pub use sigma::{SigmaProof, proof_types};
pub use range::RangeProof;
pub use equality::EqualityProof;
pub use membership::MembershipProof;
pub use plonk::{PlonkProof, PlonkEvaluations, PlonkCircuit, plonk_prove, plonk_verify};
// Re-export verifier
pub use verifier::{ZkResult, ProofSystem, KernelZkVerifier, KERNEL_ZK_VERIFIER};
// Re-export syscall interface
pub use syscall::{
    ZkError, syscall_zk_verify, syscall_zk_commit,
    syscall_zk_prove_schnorr, syscall_zk_prove_plonk,
};
