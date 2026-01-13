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

use crate::crypto::ed25519::KeyPair;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProof;
use super::range::RangeProof;

#[test]
fn test_pedersen_commitment() {
    let value = [1u8; 32];
    let blinding = [2u8; 32];

    let comm = PedersenCommitment::commit(&value, &blinding);
    assert!(comm.verify(&value, &blinding));

    let wrong_value = [3u8; 32];
    assert!(!comm.verify(&wrong_value, &blinding));
}

#[test]
fn test_schnorr_proof() {
    let secret = [42u8; 32];
    let keypair = KeyPair::from_seed(secret);

    let proof = SchnorrProof::prove(&secret, &keypair.public);
    assert!(proof.verify(&keypair.public));
}

#[test]
fn test_range_proof() {
    let proof = RangeProof::prove(100, 8).unwrap();
    assert!(proof.verify());

    assert!(RangeProof::prove(300, 8).is_err());
}
