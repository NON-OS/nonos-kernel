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
pub enum AuthError {
    EmptyCode,
    InvalidSignatureLength,
    InvalidPublicKeyLength,
    Ed25519VerificationFailed,
    DilithiumVerificationFailed,
    AttestationFailed,
    TrustedKeyNotFound,
    HashMismatch,
    InvalidFormat,
}

impl AuthError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyCode => "Empty code",
            Self::InvalidSignatureLength => "Invalid signature length",
            Self::InvalidPublicKeyLength => "Invalid public key length",
            Self::Ed25519VerificationFailed => "Ed25519 verification failed",
            Self::DilithiumVerificationFailed => "Dilithium verification failed",
            Self::AttestationFailed => "Attestation failed",
            Self::TrustedKeyNotFound => "Trusted key not found",
            Self::HashMismatch => "Hash mismatch",
            Self::InvalidFormat => "Invalid format",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::EmptyCode => -22,
            Self::InvalidSignatureLength => -22,
            Self::InvalidPublicKeyLength => -22,
            Self::Ed25519VerificationFailed => -1,
            Self::DilithiumVerificationFailed => -1,
            Self::AttestationFailed => -1,
            Self::TrustedKeyNotFound => -2,
            Self::HashMismatch => -5,
            Self::InvalidFormat => -22,
        }
    }
}

pub type AuthResult<T> = Result<T, AuthError>;
