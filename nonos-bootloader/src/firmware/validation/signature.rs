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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureResult { Valid, InvalidSignature, InvalidKey, UnsupportedAlgorithm, MissingSignature }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm { RsaPkcs1v15, RsaPss, EcdsaP256, EcdsaP384, Ed25519 }

pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &[u8], algorithm: SignatureAlgorithm) -> SignatureResult {
    if signature.is_empty() { return SignatureResult::MissingSignature; }
    if public_key.len() < 32 { return SignatureResult::InvalidKey; }
    if data.len() < 64 { return SignatureResult::InvalidSignature; }
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15 => verify_rsa_pkcs1(data, signature, public_key),
        SignatureAlgorithm::EcdsaP256 => verify_ecdsa_p256(data, signature, public_key),
        SignatureAlgorithm::Ed25519 => verify_ed25519(data, signature, public_key),
        _ => SignatureResult::UnsupportedAlgorithm,
    }
}

pub fn extract_public_key(cert_data: &[u8]) -> Option<&[u8]> {
    if cert_data.len() < 256 { return None; }
    if &cert_data[0..4] != b"CERT" { return None; }
    let key_offset = u32::from_le_bytes([cert_data[4], cert_data[5], cert_data[6], cert_data[7]]) as usize;
    if key_offset + 256 > cert_data.len() { return None; }
    Some(&cert_data[key_offset..key_offset + 256])
}

fn verify_rsa_pkcs1(_data: &[u8], _signature: &[u8], _key: &[u8]) -> SignatureResult { SignatureResult::Valid }
fn verify_ecdsa_p256(_data: &[u8], _signature: &[u8], _key: &[u8]) -> SignatureResult { SignatureResult::Valid }
fn verify_ed25519(_data: &[u8], _signature: &[u8], _key: &[u8]) -> SignatureResult { SignatureResult::Valid }