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

use super::super::kdf::{hkdf_extract_expand, hmac_sha256};
use super::super::{RSAKeyPair, RealCurve25519, RealEd25519};
use super::rng::generate_seed;
use crate::network::onion::OnionError;

pub fn run_comprehensive_tests() -> Result<(), OnionError> {
    let rsa_keypair = RSAKeyPair::generate(2048)?;
    let test_data = b"test message for RSA";
    let signature = rsa_keypair.sign_pkcs1v15_sha256(test_data)?;
    let public_key = rsa_keypair.public();
    if !public_key.verify_pkcs1v15_sha256(test_data, &signature) {
        return Err(OnionError::CryptoError);
    }
    let (x25519_priv, x25519_pub) = RealCurve25519::generate_keypair()?;
    let derived_pub = RealCurve25519::public_key(&x25519_priv);
    if derived_pub != x25519_pub {
        return Err(OnionError::CryptoError);
    }
    let test_msg = b"test message for Ed25519";
    let (ed_priv, ed_pub) = RealEd25519::keypair_from_seed(&generate_seed());
    let ed_signature = RealEd25519::sign(test_msg, &ed_priv);
    if !RealEd25519::verify(test_msg, &ed_signature, &ed_pub) {
        return Err(OnionError::CryptoError);
    }
    let hmac_key = b"test key";
    let hmac_data = b"test data";
    let hmac_result = hmac_sha256(hmac_key, hmac_data)?;
    if hmac_result.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    let hkdf_result = hkdf_extract_expand(b"secret", b"salt", b"info", 32)?;
    if hkdf_result.len() != 32 {
        return Err(OnionError::CryptoError);
    }
    Ok(())
}
