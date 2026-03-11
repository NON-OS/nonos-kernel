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


use alloc::vec::Vec;

pub struct X509Certificate {
    pub tbs_certificate: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub public_key: PublicKeyInfo,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub is_ca: bool,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
}

pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Vec<u8>>,
}

pub struct PublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: Vec<u8>,
    pub raw_spki: Vec<u8>,
}

pub struct ObjectIdentifier {
    pub components: Vec<u32>,
}

impl ObjectIdentifier {
    const RSA_ENCRYPTION: [u32; 7] = [1, 2, 840, 113549, 1, 1, 1];
    const RSA_SHA256: [u32; 7] = [1, 2, 840, 113549, 1, 1, 11];
    const ED25519: [u32; 4] = [1, 3, 101, 112];
    const EC_PUBLIC_KEY: [u32; 6] = [1, 2, 840, 10045, 2, 1];
    const ECDSA_SHA256: [u32; 7] = [1, 2, 840, 10045, 4, 3, 2];

    pub fn is_rsa_encryption(&self) -> bool {
        self.components == Self::RSA_ENCRYPTION || self.components == Self::RSA_SHA256
    }

    pub fn is_ed25519(&self) -> bool {
        self.components == Self::ED25519
    }

    pub fn is_ec_public_key(&self) -> bool {
        self.components == Self::EC_PUBLIC_KEY
    }

    pub fn is_ecdsa_sha256(&self) -> bool {
        self.components == Self::ECDSA_SHA256
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyKind {
    Rsa,
    Ed25519,
    EcdsaP256,
    X25519,
}
