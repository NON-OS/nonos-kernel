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

mod types;
mod rsa;
mod curve;
mod dh;
mod kdf;
mod x509_der;
mod x509_time;
mod x509_verify;
mod x509_core;
mod x509_san;
mod aead;
mod util;
mod verify;

pub use types::{X509Certificate, AlgorithmIdentifier, PublicKeyInfo, ObjectIdentifier, PublicKeyKind, X509Extensions, BasicConstraints, ExtKeyUsage};
pub use rsa::{RSAKeyPair, RSAPublic, RealRSA};
pub use curve::{RealCurve25519, RealEd25519, scalar_mult_x25519, ed25519_verify, x25519_keypair, x25519};
pub use dh::RealDH;
pub use kdf::{hmac_sha256, hkdf_extract_expand, hkdf_extract_sha256, hkdf_expand_sha256, derive_layer_keys, ntor_derive_keys};
pub use kdf::{hmac_sha384, hkdf_extract_sha384, hkdf_expand_sha384};
#[cfg(feature = "sha1-legacy")]
pub use kdf::tap_derive_keys;
pub use x509_core::X509;
pub(crate) use x509_verify::verify_signature_with_spki_der;
pub(crate) use x509_verify::{check_eku_server_auth, check_leaf_key_usage};
pub(crate) use x509_verify::dn_equal;
pub use aead::{
    aes128_gcm_seal, aes128_gcm_open, chacha20poly1305_seal, chacha20poly1305_open,
    tls_aes128_gcm_seal, tls_aes128_gcm_open, tls_chacha20poly1305_seal, tls_chacha20poly1305_open,
    tls_aes256_gcm_seal, tls_aes256_gcm_open,
};
pub use util::{VaultRng, generate_seed, constant_time_eq, secure_memzero, conditional_select, rand32, sha256};
pub use verify::{rsa_pss_sha256_verify_spki, rsa_pss_sha384_verify_spki, rsa_pkcs1v15_sha256_verify_spki, rsa_pkcs1v15_sha384_verify_spki, ecdsa_p256_sha256_verify_spki, ecdsa_p384_sha384_verify_spki};
