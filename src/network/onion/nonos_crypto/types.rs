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

use alloc::string::String;
use alloc::vec::Vec;

/// Key Usage bit flags (RFC 5280 §4.2.1.3)
/// ASN.1 BIT STRING is MSB-first: bit 0 = 0x80 of byte 0, bit 7 = 0x01.
pub(crate) const KU_DIGITAL_SIGNATURE: u16 = 0x80; // bit 0
pub(crate) const KU_KEY_ENCIPHERMENT: u16 = 0x20; // bit 2
pub(crate) const KU_KEY_CERT_SIGN: u16 = 0x04; // bit 5

/// Extended Key Usage purposes (RFC 5280 §4.2.1.12)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKeyUsage {
    ServerAuth,
    ClientAuth,
    OcspSigning,
}

/// Basic Constraints (RFC 5280 §4.2.1.9)
#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u8>,
}

impl Default for BasicConstraints {
    fn default() -> Self {
        Self { ca: false, path_len_constraint: None }
    }
}

/// Parsed X.509v3 extensions
pub struct X509Extensions {
    pub basic_constraints: BasicConstraints,
    pub key_usage: u16,
    pub ext_key_usage: Vec<ExtKeyUsage>,
    pub subject_key_id: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
    /// DNS names from the Subject Alternative Name extension (RFC 5280 §4.2.1.6)
    pub san_dns_names: Vec<String>,
}

impl Default for X509Extensions {
    fn default() -> Self {
        Self {
            basic_constraints: BasicConstraints::default(),
            key_usage: 0,
            ext_key_usage: Vec::new(),
            subject_key_id: None,
            authority_key_id: None,
            san_dns_names: Vec::new(),
        }
    }
}

pub struct X509Certificate {
    pub tbs_certificate: Vec<u8>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub public_key: PublicKeyInfo,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub extensions: X509Extensions,
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
    const RSA_SHA384: [u32; 7] = [1, 2, 840, 113549, 1, 1, 12];
    const RSA_SHA512: [u32; 7] = [1, 2, 840, 113549, 1, 1, 13];
    const ED25519: [u32; 4] = [1, 3, 101, 112];
    const EC_PUBLIC_KEY: [u32; 6] = [1, 2, 840, 10045, 2, 1];
    const ECDSA_SHA256: [u32; 7] = [1, 2, 840, 10045, 4, 3, 2];
    const ECDSA_SHA384: [u32; 7] = [1, 2, 840, 10045, 4, 3, 3];
    #[allow(dead_code)]
    const SECP256R1: [u32; 7] = [1, 2, 840, 10045, 3, 1, 7];
    pub(crate) const SECP384R1: [u32; 5] = [1, 3, 132, 0, 34];

    pub fn is_rsa_encryption(&self) -> bool {
        self.components == Self::RSA_ENCRYPTION
            || self.components == Self::RSA_SHA256
            || self.components == Self::RSA_SHA384
            || self.components == Self::RSA_SHA512
    }

    pub fn is_ed25519(&self) -> bool {
        self.components == Self::ED25519
    }

    pub fn is_ec_public_key(&self) -> bool {
        self.components == Self::EC_PUBLIC_KEY
    }

    pub fn is_ecdsa(&self) -> bool {
        self.components == Self::ECDSA_SHA256 || self.components == Self::ECDSA_SHA384
    }

    pub fn is_ecdsa_sha256(&self) -> bool {
        self.components == Self::ECDSA_SHA256
    }

    pub fn is_rsa_sha384(&self) -> bool {
        self.components == Self::RSA_SHA384
    }

    pub fn is_rsa_sha512(&self) -> bool {
        self.components == Self::RSA_SHA512
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyKind {
    Rsa,
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    X25519,
}
