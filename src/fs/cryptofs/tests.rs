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

use super::crypto::{generate_nonce, validate_path};
use super::error::CryptoFsError;
use super::types::{secure_zeroize, MAX_PATH_LEN};

#[test]
fn test_crypto_error_to_errno() {
    assert_eq!(CryptoFsError::NotFound.to_errno(), -2);
    assert_eq!(CryptoFsError::AlreadyExists.to_errno(), -17);
    assert_eq!(CryptoFsError::PathTooLong.to_errno(), -36);
}

#[test]
fn test_validate_path() {
    assert!(validate_path("/test/file").is_ok());
    assert!(validate_path("").is_err());
    assert!(validate_path(&"x".repeat(MAX_PATH_LEN + 1)).is_err());
}

#[test]
fn test_nonce_generation() {
    let nonce1 = generate_nonce(0);
    let nonce2 = generate_nonce(1);
    assert_ne!(nonce1[4..12], nonce2[4..12]);
}

#[test]
fn test_secure_zeroize() {
    let mut data = [0xFFu8; 32];
    secure_zeroize(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}
