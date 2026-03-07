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

/*
 * Common error types for the cryptography subsystem.
 *
 * CryptoError covers failures across all crypto operations:
 * - Symmetric encryption (AEAD tag verification)
 * - Key management (invalid keys, missing keys)
 * - Signature operations (verification failures)
 * - General validation (buffer sizes, input format)
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    AeadTagMismatch,
    InvalidLength,
    KemError,
    SigError,
    InvalidInput,
    InvalidKey,
    KeyNotFound,
    BufferTooSmall,
    VerificationFailed,
    InvalidState,
    AuthenticationFailed,
}

pub type CryptoResult<T> = Result<T, CryptoError>;
