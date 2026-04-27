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

use crate::zk_engine::{generate_plonk_proof, verify_plonk_proof};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static PROOFS_GENERATED: AtomicU64 = AtomicU64::new(0);
static PROOFS_VERIFIED: AtomicU64 = AtomicU64::new(0);

pub(super) fn generate_proof(
    circuit_id: u32,
    witness: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
) -> Option<Vec<u8>> {
    match generate_plonk_proof(circuit_id, witness, public_inputs) {
        Ok(proof) => {
            PROOFS_GENERATED.fetch_add(1, Ordering::Relaxed);
            Some(proof)
        }
        Err(_) => None,
    }
}

pub(super) fn verify_proof(proof_data: &[u8]) -> bool {
    let result = verify_plonk_proof(proof_data).unwrap_or(false);
    PROOFS_VERIFIED.fetch_add(1, Ordering::Relaxed);
    result
}

pub(super) fn get_stats() -> (u64, u64) {
    (PROOFS_GENERATED.load(Ordering::Relaxed), PROOFS_VERIFIED.load(Ordering::Relaxed))
}
