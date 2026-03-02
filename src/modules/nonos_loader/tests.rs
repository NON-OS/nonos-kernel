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
use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};

#[test]
fn test_loader_policy_default() {
    let policy = LoaderPolicy::default();
    assert!(policy.privacy_enforced);
    assert_eq!(policy.required_privacy, PrivacyPolicy::ZeroStateOnly);
    assert!(policy.enforce_attestation);
    assert!(!policy.enforce_capabilities);
    assert!(policy.sandbox_config.is_none());
}

#[test]
fn test_loader_policy_builder() {
    let policy = LoaderPolicy::new()
        .with_privacy(PrivacyPolicy::Ephemeral)
        .with_attestation()
        .with_capabilities();

    assert!(policy.privacy_enforced);
    assert_eq!(policy.required_privacy, PrivacyPolicy::Ephemeral);
    assert!(policy.enforce_attestation);
    assert!(policy.enforce_capabilities);
}

#[test]
fn test_loader_policy_disable_enforcement() {
    let policy = LoaderPolicy::new()
        .without_privacy_enforcement()
        .without_attestation();

    assert!(!policy.privacy_enforced);
    assert!(!policy.enforce_attestation);
}

#[test]
fn test_loader_request_creation() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"modcode",
    );

    let request = LoaderRequest::new(
        manifest,
        vec![1, 2, 3, 4],
        [0u8; 64],
        [0u8; 32],
    );

    assert_eq!(request.code, vec![1, 2, 3, 4]);
    assert!(request.pqc_signature.is_none());
    assert!(request.pqc_pubkey.is_none());
}

#[test]
fn test_loader_request_with_pqc() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"modcode",
    );

    let request = LoaderRequest::new(manifest, vec![1, 2, 3, 4], [0u8; 64], [0u8; 32])
        .with_pqc(vec![5, 6, 7], vec![8, 9, 10]);

    assert_eq!(request.pqc_signature, Some(vec![5, 6, 7]));
    assert_eq!(request.pqc_pubkey, Some(vec![8, 9, 10]));
}

#[test]
fn test_load_privacy_policy_enforced() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Anon".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"modcode",
    );

    let request = LoaderRequest::new(manifest, vec![1, 2, 3, 4, 5, 6, 7, 8], [0u8; 64], [0u8; 32]);

    let policy = LoaderPolicy::new().with_privacy(PrivacyPolicy::Ephemeral);

    let result = load(request, &policy);
    assert_eq!(result, Err(LoaderError::PrivacyPolicyMismatch));
}

#[test]
fn test_load_no_capabilities_enforced() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Anon".into(),
        "Desc".into(),
        vec![], // No capabilities
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"modcode",
    );

    let request = LoaderRequest::new(manifest, vec![1, 2, 3, 4], [0u8; 64], [0u8; 32]);

    let policy = LoaderPolicy::new()
        .without_attestation()
        .with_capabilities();

    let result = load(request, &policy);
    assert_eq!(result, Err(LoaderError::NoCapabilities));
}

#[test]
fn test_error_messages() {
    assert_eq!(
        LoaderError::PrivacyPolicyMismatch.as_str(),
        "Privacy policy mismatch"
    );
    assert_eq!(
        LoaderError::AttestationFailed.as_str(),
        "Attestation chain not trusted"
    );
    assert_eq!(
        LoaderError::AuthenticationFailed.as_str(),
        "Module authentication failed"
    );
    assert_eq!(LoaderError::LoadFailed.as_str(), "Failed to load module code");
}
