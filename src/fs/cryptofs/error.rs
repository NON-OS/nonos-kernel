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
pub enum CryptoFsError {
    NotInitialized,
    NotFound,
    AlreadyExists,
    PathTooLong,
    InvalidPath,
    DataTooShort,
    DecryptionFailed,
    EncryptionFailed,
    FileTooLarge,
    AuthenticationFailed,
    RngFailed,
    OutOfMemory,
    NonceExhausted,
    InternalError(&'static str),
}

impl CryptoFsError {
    pub const fn to_errno(self) -> i32 {
        match self {
            CryptoFsError::NotInitialized => -5,
            CryptoFsError::NotFound => -2,
            CryptoFsError::AlreadyExists => -17,
            CryptoFsError::PathTooLong => -36,
            CryptoFsError::InvalidPath => -22,
            CryptoFsError::DataTooShort => -22,
            CryptoFsError::DecryptionFailed => -5,
            CryptoFsError::EncryptionFailed => -5,
            CryptoFsError::FileTooLarge => -27,
            CryptoFsError::AuthenticationFailed => -5,
            CryptoFsError::RngFailed => -5,
            CryptoFsError::OutOfMemory => -12,
            CryptoFsError::NonceExhausted => -5,
            CryptoFsError::InternalError(_) => -5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            CryptoFsError::NotInitialized => "CryptoFS not initialized",
            CryptoFsError::NotFound => "File not found",
            CryptoFsError::AlreadyExists => "File already exists",
            CryptoFsError::PathTooLong => "Path too long",
            CryptoFsError::InvalidPath => "Invalid path",
            CryptoFsError::DataTooShort => "Encrypted data too short",
            CryptoFsError::DecryptionFailed => "Decryption failed",
            CryptoFsError::EncryptionFailed => "Encryption failed",
            CryptoFsError::FileTooLarge => "File too large",
            CryptoFsError::AuthenticationFailed => "Authentication failed",
            CryptoFsError::RngFailed => "Random generation failed",
            CryptoFsError::OutOfMemory => "Out of memory",
            CryptoFsError::NonceExhausted => "Nonce counter exhausted",
            CryptoFsError::InternalError(msg) => msg,
        }
    }
}

impl From<CryptoFsError> for &'static str {
    fn from(err: CryptoFsError) -> Self {
        err.as_str()
    }
}

pub type CryptoResult<T> = Result<T, CryptoFsError>;
