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
use crate::test::framework::TestResult;

pub(crate) fn test_zk_identity_empty() -> TestResult {
    let identity = ZkIdentity::empty();
    if identity.id != [0u8; 32] {
        return TestResult::Fail;
    }
    if identity.commitment != [0u8; 32] {
        return TestResult::Fail;
    }
    if identity.active {
        return TestResult::Fail;
    }
    if identity.created_epoch != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_identity_generate() -> TestResult {
    let identity = ZkIdentity::generate(100);
    if !identity.active {
        return TestResult::Fail;
    }
    if identity.created_epoch != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_identity_generate_unique() -> TestResult {
    let id1 = ZkIdentity::generate(100);
    let id2 = ZkIdentity::generate(100);
    if id1.id == id2.id {
        return TestResult::Fail;
    }
    if id1.commitment == id2.commitment {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_identity_short_id_length() -> TestResult {
    let identity = ZkIdentity::generate(100);
    let short = identity.short_id();
    if short.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zk_identity_short_id_hex() -> TestResult {
    let mut identity = ZkIdentity::empty();
    identity.id[0] = 0xAB;
    let short = identity.short_id();
    if short[0] != b'a' {
        return TestResult::Fail;
    }
    if short[1] != b'b' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_new() -> TestResult {
    let state = PrivacyState::new();
    if state.identity_count != 0 {
        return TestResult::Fail;
    }
    if state.active_identity != 0 {
        return TestResult::Fail;
    }
    if !state.stealth_enabled {
        return TestResult::Fail;
    }
    if !state.fingerprint_protection {
        return TestResult::Fail;
    }
    if !state.request_padding {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_create_identity() -> TestResult {
    let mut state = PrivacyState::new();
    let result = state.create_identity(100);
    if result.is_none() {
        return TestResult::Fail;
    }
    if result.unwrap() != 0 {
        return TestResult::Fail;
    }
    if state.identity_count != 1 {
        return TestResult::Fail;
    }
    if state.active_identity != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_create_identity_multiple() -> TestResult {
    let mut state = PrivacyState::new();
    if state.create_identity(100) != Some(0) {
        return TestResult::Fail;
    }
    if state.create_identity(101) != Some(1) {
        return TestResult::Fail;
    }
    if state.create_identity(102) != Some(2) {
        return TestResult::Fail;
    }
    if state.identity_count != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_create_identity_max() -> TestResult {
    let mut state = PrivacyState::new();
    for i in 0..MAX_IDENTITIES {
        if state.create_identity(i as u64).is_none() {
            return TestResult::Fail;
        }
    }
    if state.identity_count != MAX_IDENTITIES {
        return TestResult::Fail;
    }
    if state.create_identity(100).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_create_identity_sets_active() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    if state.active_identity != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_switch_identity() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    if !state.switch_identity(1) {
        return TestResult::Fail;
    }
    if state.active_identity != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_switch_identity_invalid_index() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    if state.switch_identity(5) {
        return TestResult::Fail;
    }
    if state.active_identity != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_switch_identity_inactive() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.deactivate_identity(1);
    if state.switch_identity(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_deactivate_identity() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    if !state.deactivate_identity(0) {
        return TestResult::Fail;
    }
    if state.identities[0].active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_deactivate_identity_invalid() -> TestResult {
    let mut state = PrivacyState::new();
    if state.deactivate_identity(5) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_get_active_none() -> TestResult {
    let state = PrivacyState::new();
    if state.get_active().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_get_active_some() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    let active = state.get_active();
    if active.is_none() {
        return TestResult::Fail;
    }
    if !active.unwrap().active {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_active_count_none() -> TestResult {
    let state = PrivacyState::new();
    if state.active_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_active_count_all() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.create_identity(102);
    if state.active_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_active_count_partial() -> TestResult {
    let mut state = PrivacyState::new();
    state.create_identity(100);
    state.create_identity(101);
    state.create_identity(102);
    state.deactivate_identity(1);
    if state.active_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_enable_stealth() -> TestResult {
    let mut state = PrivacyState::new();
    state.disable_stealth();
    state.enable_stealth();
    if !state.stealth_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_disable_stealth() -> TestResult {
    let mut state = PrivacyState::new();
    state.disable_stealth();
    if state.stealth_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_set_fingerprint_protection_on() -> TestResult {
    let mut state = PrivacyState::new();
    state.set_fingerprint_protection(false);
    state.set_fingerprint_protection(true);
    if !state.fingerprint_protection {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_set_fingerprint_protection_off() -> TestResult {
    let mut state = PrivacyState::new();
    state.set_fingerprint_protection(false);
    if state.fingerprint_protection {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_set_request_padding_on() -> TestResult {
    let mut state = PrivacyState::new();
    state.set_request_padding(false);
    state.set_request_padding(true);
    if !state.request_padding {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_set_request_padding_off() -> TestResult {
    let mut state = PrivacyState::new();
    state.set_request_padding(false);
    if state.request_padding {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_state_default() -> TestResult {
    let state = PrivacyState::default();
    if state.identity_count != 0 {
        return TestResult::Fail;
    }
    if !state.stealth_enabled {
        return TestResult::Fail;
    }
    if !state.fingerprint_protection {
        return TestResult::Fail;
    }
    if !state.request_padding {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privacy_constants() -> TestResult {
    if MAX_IDENTITIES != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
