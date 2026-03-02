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
pub enum KeyType {
    Ed25519Signing,
    Ed25519Verify,
    X25519Exchange,
    Aes256,
    ChaCha20,
    Hmac,
    MasterKey,
    MlKemEncap,
    MlKemDecap,
    MlDsaSign,
    MlDsaVerify,
}

impl KeyType {
    pub fn key_length(&self) -> usize {
        match self {
            KeyType::Ed25519Signing => 32,
            KeyType::Ed25519Verify => 32,
            KeyType::X25519Exchange => 32,
            KeyType::Aes256 => 32,
            KeyType::ChaCha20 => 32,
            KeyType::Hmac => 32,
            KeyType::MasterKey => 32,
            KeyType::MlKemEncap => 1184,
            KeyType::MlKemDecap => 2400,
            KeyType::MlDsaSign => 4032,
            KeyType::MlDsaVerify => 1952,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    pub encrypt: bool,
    pub decrypt: bool,
    pub sign: bool,
    pub verify: bool,
    pub derive: bool,
    pub exportable: bool,
}

impl KeyUsage {
    pub const fn signing() -> Self {
        Self { encrypt: false, decrypt: false, sign: true, verify: false, derive: false, exportable: false }
    }

    pub const fn verification() -> Self {
        Self { encrypt: false, decrypt: false, sign: false, verify: true, derive: false, exportable: true }
    }

    pub const fn encryption() -> Self {
        Self { encrypt: true, decrypt: true, sign: false, verify: false, derive: false, exportable: false }
    }

    pub const fn key_exchange() -> Self {
        Self { encrypt: false, decrypt: false, sign: false, verify: false, derive: true, exportable: false }
    }

    pub const fn master() -> Self {
        Self { encrypt: false, decrypt: false, sign: false, verify: false, derive: true, exportable: false }
    }
}
