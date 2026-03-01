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

extern crate alloc;
use alloc::vec::Vec;
use super::types::QuantumAlgorithm;

pub fn generate_pq_keypair(algo: &QuantumAlgorithm) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_keypair(),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_keypair(),
        QuantumAlgorithm::Dilithium3 => crate::crypto::quantum::dilithium3_keypair(),
        QuantumAlgorithm::SphincsPlus128s => crate::crypto::quantum::sphincs128s_keypair(),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_keypair(),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_keypair(),
        QuantumAlgorithm::Lattice => crate::crypto::quantum::lattice_keypair(),
    }
}

pub fn pq_sign(algo: &QuantumAlgorithm, message: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
    match algo {
        QuantumAlgorithm::Dilithium3 => crate::crypto::quantum::dilithium3_sign(message, sk),
        QuantumAlgorithm::SphincsPlus128s => crate::crypto::quantum::sphincs128s_sign(message, sk),
        _ => Err("Signing not supported for this algorithm"),
    }
}

pub fn pq_verify(algo: &QuantumAlgorithm, message: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool, &'static str> {
    match algo {
        QuantumAlgorithm::Dilithium3 => Ok(crate::crypto::quantum::dilithium3_verify(message, sig, pk)),
        QuantumAlgorithm::SphincsPlus128s => Ok(crate::crypto::quantum::sphincs128s_verify(message, sig, pk)),
        _ => Err("Verification not supported for this algorithm"),
    }
}

pub fn pq_encapsulate(algo: &QuantumAlgorithm, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_encapsulate(pk),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_encapsulate(pk),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_encapsulate(pk),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_encapsulate(pk),
        _ => Err("Encapsulation not supported for this algorithm"),
    }
}

pub fn pq_decapsulate(algo: &QuantumAlgorithm, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, &'static str> {
    match algo {
        QuantumAlgorithm::Kyber1024 => crate::crypto::quantum::kyber1024_decapsulate(ct, sk),
        QuantumAlgorithm::Kyber768 => crate::crypto::quantum::kyber768_decapsulate(ct, sk),
        QuantumAlgorithm::NtruHps4096821 => crate::crypto::quantum::ntruhps4096821_decapsulate(ct, sk),
        QuantumAlgorithm::McEliece348864 => crate::crypto::quantum::mceliece348864_decapsulate(ct, sk),
        _ => Err("Decapsulation not supported for this algorithm"),
    }
}
