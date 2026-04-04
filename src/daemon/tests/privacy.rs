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

use crate::daemon::*;

#[test]
fn test_zk_identity_empty() {
    let identity = ZkIdentity::empty();
    assert_eq!(identity.id, [0u8; 32]);
    assert_eq!(identity.commitment, [0u8; 32]);
    assert!(!identity.active);
    assert_eq!(identity.created_epoch, 0);
}

#[test]
fn test_zk_identity_generate() {
    let identity = ZkIdentity::generate(100);
    assert!(identity.active);
    assert_eq!(identity.created_epoch, 100);
}

#[test]
fn test_zk_identity_generate_unique() {
    let id1 = ZkIdentity::generate(100);
    let id2 = ZkIdentity::generate(100);
    assert_ne!(id1.id, id2.id);
    assert_ne!(id1.commitment, id2.commitment);
}

#[test]
fn test_zk_identity_short_id_length() {
    let identity = ZkIdentity::generate(100);
    let short = identity.short_id();
    assert_eq!(short.len(), 16);
}

#[test]
fn test_zk_identity_short_id_hex() {
    let mut identity = ZkIdentity::empty();
    identity.id[0] = 0xAB;
    let short = identity.short_id();
    assert_eq!(short[0], b'a');
    assert_eq!(short[1], b'b');
}

#[test]
fn test_privacy_state_new() {
    let state = PrivacyState::new();
    assert_eq!(state.identity_count, 0);
    assert_eq!(state.active_identity, 0);
    assert!(state.stealth_enabled);
    assert!(state.fingerprint_protection);
    assert!(state.request_padding);
}

#[test]
fn test_privacy_state_create_identity() {
    let mut state = PrivacyState::new();
    let result = state.create_identity(100);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(state.identity_count, 1);
    assert_eq!(state.active_identity, 0);
}

#[test]
fn test_privacy_state_create_identity_multiple() {
    let mut state = PrivacyState::new();
    assert_eq!(state.create_identity(100), Some(0));
    assert_eq!(state.create_identity(101), Some(1));
    assert_eq!(state.create_identity(102), Some(2));
    assert_eq!(state.identity_count, 3);
}

#[test]
fn test_privacy_state_create_identity_max() {
    let mut state = PrivacyState::new();
    for i in 0..MAX_IDENTITIES {
        assert!(state.create_identity(i as u64).is_some());
    }
    assert_eq!(state.identity_count, MAX_IDENTITIES);
    assert!(state.create_identity(100).is_none());
}

#[test]
fn test_privacy_state_create_identity_sets_active() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    assert_eq!(state.active_identity, 0);
}

#[test]
fn test_privacy_state_switch_identity() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    assert!(state.switch_identity(1));
    assert_eq!(state.active_identity, 1);
}

#[test]
fn test_privacy_state_switch_identity_invalid_index() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    assert!(!state.switch_identity(5));
    assert_eq!(state.active_identity, 0);
}

#[test]
fn test_privacy_state_switch_identity_inactive() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.deactivate_identity(1);
    assert!(!state.switch_identity(1));
}

#[test]
fn test_privacy_state_deactivate_identity() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    assert!(state.deactivate_identity(0));
    assert!(!state.identities[0].active);
}

#[test]
fn test_privacy_state_deactivate_identity_invalid() {
    let mut state = PrivacyState::new();
    assert!(!state.deactivate_identity(5));
}

#[test]
fn test_privacy_state_get_active_none() {
    let state = PrivacyState::new();
    assert!(state.get_active().is_none());
}

#[test]
fn test_privacy_state_get_active_some() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    let active = state.get_active();
    assert!(active.is_some());
    assert!(active.unwrap().active);
}

#[test]
fn test_privacy_state_active_count_none() {
    let state = PrivacyState::new();
    assert_eq!(state.active_count(), 0);
}

#[test]
fn test_privacy_state_active_count_all() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.create_identity(102);
    assert_eq!(state.active_count(), 3);
}

#[test]
fn test_privacy_state_active_count_partial() {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.create_identity(102);
    state.deactivate_identity(1);
    assert_eq!(state.active_count(), 2);
}

#[test]
fn test_privacy_state_enable_stealth() {
    let mut state = PrivacyState::new();
    state.disable_stealth();
    state.enable_stealth();
    assert!(state.stealth_enabled);
}

#[test]
fn test_privacy_state_disable_stealth() {
    let mut state = PrivacyState::new();
    state.disable_stealth();
    assert!(!state.stealth_enabled);
}

#[test]
fn test_privacy_state_set_fingerprint_protection_on() {
    let mut state = PrivacyState::new();
    state.set_fingerprint_protection(false);
    state.set_fingerprint_protection(true);
    assert!(state.fingerprint_protection);
}

#[test]
fn test_privacy_state_set_fingerprint_protection_off() {
    let mut state = PrivacyState::new();
    state.set_fingerprint_protection(false);
    assert!(!state.fingerprint_protection);
}

#[test]
fn test_privacy_state_set_request_padding_on() {
    let mut state = PrivacyState::new();
    state.set_request_padding(false);
    state.set_request_padding(true);
    assert!(state.request_padding);
}

#[test]
fn test_privacy_state_set_request_padding_off() {
    let mut state = PrivacyState::new();
    state.set_request_padding(false);
    assert!(!state.request_padding);
}

#[test]
fn test_privacy_state_default() {
    let state = PrivacyState::default();
    assert_eq!(state.identity_count, 0);
    assert!(state.stealth_enabled);
    assert!(state.fingerprint_protection);
    assert!(state.request_padding);
}

#[test]
fn test_privacy_constants() {
    assert_eq!(MAX_IDENTITIES, 8);
}
