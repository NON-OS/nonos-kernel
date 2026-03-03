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
}

pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Vec<u8>>,
}

pub struct PublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: Vec<u8>,
}

pub struct ObjectIdentifier {
    pub components: Vec<u32>,
}

impl ObjectIdentifier {
    const RSA_ENCRYPTION: [u32; 7] = [1, 2, 840, 113549, 1, 1, 1];
    const ED25519: [u32; 4] = [1, 3, 101, 112];

    pub fn is_rsa_encryption(&self) -> bool {
        self.components == Self::RSA_ENCRYPTION
    }

    pub fn is_ed25519(&self) -> bool {
        self.components == Self::ED25519
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyKind {
    Rsa,
    Ed25519,
    X25519,
}
