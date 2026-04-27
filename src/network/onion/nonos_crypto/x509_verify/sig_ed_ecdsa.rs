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

use crate::network::onion::OnionError;
use crate::sys::serial;
use super::super::curve::RealEd25519;
use super::super::types::X509Certificate;

pub(super) fn verify_ed25519(cert: &X509Certificate, public_key_bytes: &[u8]) -> Result<(), OnionError> {
    if public_key_bytes.len() != 32 || cert.signature.len() != 64 {
        serial::println(b"[X509] Ed25519 wrong lengths");
        return Err(OnionError::CryptoError);
    }
    let mut public_key = [0u8; 32];
    let mut signature = [0u8; 64];
    public_key.copy_from_slice(public_key_bytes);
    signature.copy_from_slice(&cert.signature);
    if RealEd25519::verify(&cert.tbs_certificate, &signature, &public_key) {
        Ok(())
    } else {
        serial::println(b"[X509] Ed25519 verify FAILED");
        Err(OnionError::CryptoError)
    }
}

pub(super) fn verify_ecdsa(cert: &X509Certificate, public_key_bytes: &[u8], is_sha256: bool) -> Result<(), OnionError> {
    if is_sha256 {
        match super::super::ecdsa_p256_sha256_verify_spki(public_key_bytes, &cert.tbs_certificate, &cert.signature) {
            Ok(true) => Ok(()),
            Ok(false) => {
                serial::println(b"[X509] ECDSA verify FAILED");
                Err(OnionError::CryptoError)
            }
            Err(e) => {
                serial::println(b"[X509] ECDSA verify ERROR");
                Err(e)
            }
        }
    } else {
        match super::super::ecdsa_p384_sha384_verify_spki(public_key_bytes, &cert.tbs_certificate, &cert.signature) {
            Ok(true) => Ok(()),
            Ok(false) => {
                serial::println(b"[X509] ECDSA P384 verify FAILED");
                Err(OnionError::CryptoError)
            }
            Err(e) => {
                serial::println(b"[X509] ECDSA P384 verify ERROR");
                Err(e)
            }
        }
    }
}
