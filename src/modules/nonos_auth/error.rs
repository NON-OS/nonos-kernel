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
    InvalidSignatureLength,
    Ed25519VerificationFailed,
    InvalidDilithiumSignatureLength,
    InvalidDilithiumKeyLength,
    DilithiumDeserializationFailed,
    DilithiumVerificationFailed,
    AttestationFailed,
    NoTrustedKeyMatch,
    SecureEraseFailed,
}

impl AuthError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignatureLength => "Invalid signature length",
            Self::Ed25519VerificationFailed => "Ed25519 verification failed",
            Self::InvalidDilithiumSignatureLength => "Invalid Dilithium signature length",
            Self::InvalidDilithiumKeyLength => "Invalid Dilithium key length",
            Self::DilithiumDeserializationFailed => "Invalid Dilithium key/signature format",
            Self::DilithiumVerificationFailed => "Dilithium verification failed",
            Self::AttestationFailed => "Attestation chain verification failed",
            Self::NoTrustedKeyMatch => "No trusted key matched attestation",
            Self::SecureEraseFailed => "Failed to securely erase authentication context",
        }
    }
}

pub type AuthResult<T> = Result<T, AuthError>;
