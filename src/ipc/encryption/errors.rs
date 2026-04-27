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
pub enum EncryptionError {
    InvalidKey,
    InvalidNonce,
    InvalidNonceSize,
    EncryptionFailed,
    DecryptionFailed,
    InvalidSignature,
    KeyGenerationFailed,
    KeyDerivationFailed,
    BufferTooSmall,
    InvalidContext,
    InsufficientEntropy,
    AuthenticationFailed,
}

impl EncryptionError {
    pub fn as_str(&self) -> &'static str {
        match self {
            EncryptionError::InvalidKey => "Invalid encryption key",
            EncryptionError::InvalidNonce => "Invalid nonce value",
            EncryptionError::InvalidNonceSize => "Invalid nonce size",
            EncryptionError::EncryptionFailed => "Encryption operation failed",
            EncryptionError::DecryptionFailed => "Decryption operation failed",
            EncryptionError::InvalidSignature => "Invalid message signature",
            EncryptionError::KeyGenerationFailed => "Key generation failed",
            EncryptionError::KeyDerivationFailed => "Key derivation failed",
            EncryptionError::BufferTooSmall => "Output buffer too small",
            EncryptionError::InvalidContext => "Invalid encryption context",
            EncryptionError::InsufficientEntropy => "Insufficient entropy for secure operation",
            EncryptionError::AuthenticationFailed => "Authentication failed",
        }
    }

    pub fn code(&self) -> u32 {
        match self {
            EncryptionError::InvalidKey => 0x3001,
            EncryptionError::InvalidNonce => 0x3002,
            EncryptionError::InvalidNonceSize => 0x3003,
            EncryptionError::EncryptionFailed => 0x3004,
            EncryptionError::DecryptionFailed => 0x3005,
            EncryptionError::InvalidSignature => 0x3006,
            EncryptionError::KeyGenerationFailed => 0x3007,
            EncryptionError::KeyDerivationFailed => 0x3008,
            EncryptionError::BufferTooSmall => 0x3009,
            EncryptionError::InvalidContext => 0x300A,
            EncryptionError::InsufficientEntropy => 0x300B,
            EncryptionError::AuthenticationFailed => 0x300C,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        match self {
            EncryptionError::BufferTooSmall => true,
            EncryptionError::InvalidNonce => true,
            EncryptionError::InvalidNonceSize => true,
            EncryptionError::InsufficientEntropy => true,
            _ => false,
        }
    }
}

impl core::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
