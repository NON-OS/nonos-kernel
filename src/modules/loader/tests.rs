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

use super::*;
use super::super::manifest::PrivacyPolicy;

#[test]
fn test_loader_policy_default() {
    let policy = LoaderPolicy::default();
    assert!(policy.privacy_enforced);
    assert_eq!(policy.required_privacy, PrivacyPolicy::ZeroStateOnly);
    assert!(!policy.enforce_attestation);
}

#[test]
fn test_loader_policy_builder() {
    let policy = LoaderPolicy::new()
        .with_privacy(PrivacyPolicy::Ephemeral)
        .with_attestation()
        .with_capabilities();

    assert_eq!(policy.required_privacy, PrivacyPolicy::Ephemeral);
    assert!(policy.enforce_attestation);
    assert!(policy.enforce_capabilities);
}

#[test]
fn test_loader_request_creation() {
    let request = LoaderRequest::new("test", alloc::vec![1, 2, 3]);
    assert_eq!(request.name, "test");
    assert_eq!(request.code_size(), 3);
    assert!(!request.is_signed());
}

#[test]
fn test_loader_request_with_signature() {
    let request = LoaderRequest::new("test", alloc::vec![1, 2, 3])
        .with_signature([0u8; 64], [0u8; 32]);

    assert!(request.is_signed());
}

#[test]
fn test_loader_error_errno() {
    assert_eq!(LoaderError::ImageTooSmall.to_errno(), -22);
    assert_eq!(LoaderError::AuthenticationFailed.to_errno(), -1);
    assert_eq!(LoaderError::ModuleNotFound.to_errno(), -2);
}

#[test]
fn test_load_module_too_small() {
    let small_image = [0u8; 64];
    let result = load_module(&small_image, None);
    assert!(matches!(result, Err(LoaderError::ImageTooSmall)));
}
