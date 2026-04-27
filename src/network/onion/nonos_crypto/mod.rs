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

#![allow(clippy::needless_borrow)]

mod aead;
mod curve;
mod dh;
mod kdf;
mod rsa;
mod types;
mod util;
mod verify;
mod x509_core;
mod x509_der;
mod x509_san;
mod x509_time;
mod x509_verify;

pub use aead::{
    aes128_gcm_open, aes128_gcm_seal, chacha20poly1305_open, chacha20poly1305_seal,
    tls_aes128_gcm_open, tls_aes128_gcm_seal, tls_aes256_gcm_open, tls_aes256_gcm_seal,
    tls_chacha20poly1305_open, tls_chacha20poly1305_seal,
};
pub use curve::{
    ed25519_verify, scalar_mult_x25519, x25519, x25519_keypair, RealCurve25519, RealEd25519,
};
pub use dh::RealDH;
#[cfg(feature = "sha1-legacy")]
pub use kdf::tap_derive_keys;
pub use kdf::{
    derive_layer_keys, hkdf_expand_sha256, hkdf_extract_expand, hkdf_extract_sha256, hmac_sha256,
    ntor_derive_keys,
};
pub use kdf::{hkdf_expand_sha384, hkdf_extract_sha384, hmac_sha384};
pub use rsa::{RSAKeyPair, RSAPublic, RealRSA};
pub use types::{
    AlgorithmIdentifier, BasicConstraints, ExtKeyUsage, ObjectIdentifier, PublicKeyInfo,
    PublicKeyKind, X509Certificate, X509Extensions,
};
pub use util::{
    conditional_select, constant_time_eq, generate_seed, rand32, secure_memzero, sha256, VaultRng,
};
pub use verify::{
    ecdsa_p256_sha256_verify_spki, ecdsa_p384_sha384_verify_spki, rsa_pkcs1v15_sha256_verify_spki,
    rsa_pkcs1v15_sha384_verify_spki, rsa_pss_sha256_verify_spki, rsa_pss_sha384_verify_spki,
};
pub use x509_core::X509;
pub(crate) use x509_verify::dn_equal;
pub(crate) use x509_verify::verify_signature_with_spki_der;
pub(crate) use x509_verify::{check_eku_server_auth, check_leaf_key_usage};
