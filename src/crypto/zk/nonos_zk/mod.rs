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

#![allow(clippy::result_unit_err)]

mod constants;
mod types;
mod attestation;
mod commit;
mod credential;
mod zeroize;

pub use types::{AttestationProof, Credential};
pub use attestation::{create_attestation, verify_attestation};
pub use commit::{commit, verify_commitment, commit_u64};
pub use credential::{issue_credential, verify_credential};
pub use zeroize::{zeroize_mut, zeroize_array};

#[cfg(feature = "zk-halo2")]
pub mod halo2_range {
    extern crate alloc;

    use crate::crypto::zk::halo2::{Halo2Error, halo2_verify};

    pub fn verify(
        params_bytes: &[u8],
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_columns_le32: &[&[[u8; 32]]],
    ) -> Result<(), Halo2Error> {
        halo2_verify(params_bytes, vk_bytes, proof_bytes, public_inputs_columns_le32)
    }

    pub fn single_column(inputs_le32: &[[u8; 32]]) -> [&[[u8; 32]]; 1] {
        [inputs_le32]
    }
}

#[cfg(feature = "zk-groth16")]
pub mod groth16_range {
    use crate::crypto::zk::groth16::{Groth16Error, groth16_verify_bn254};

    pub fn verify(
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        public_inputs_fr_le32: &[[u8; 32]],
    ) -> Result<(), Groth16Error> {
        groth16_verify_bn254(vk_bytes, proof_bytes, public_inputs_fr_le32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::KeyPair;
    use crate::crypto::rng::get_random_bytes;

    #[test]
    fn attest_roundtrip() {
        let kp = KeyPair::from_seed([7u8; 32]);
        let data = b"attest test";
        let proof = create_attestation(data, &kp);
        assert!(verify_attestation(data, &kp.public, &proof));

        let other = KeyPair::from_seed([8u8; 32]);
        assert!(!verify_attestation(data, &other.public, &proof));
    }

    #[test]
    fn commit_roundtrip() {
        let v = b"secret";
        let r = get_random_bytes();
        let c = commit(v, &r);
        assert!(verify_commitment(&c, v, &r));

        let mut rr = r;
        rr[0] ^= 1;
        assert!(!verify_commitment(&c, v, &rr));
    }

    #[test]
    fn credential_roundtrip() {
        let issuer = KeyPair::from_seed([9u8; 32]);
        let subject = KeyPair::from_seed([1u8; 32]);
        let attrs = b"anon cred attrs";
        let cred = issue_credential(&issuer, &subject.public, attrs, 123456789);
        assert!(verify_credential(&cred));

        let mut bad = cred;
        bad.signature[1] ^= 1;
        assert!(!verify_credential(&bad));
    }
}
