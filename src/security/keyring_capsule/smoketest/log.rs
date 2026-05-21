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

use crate::security::keyring_capsule::smoketest::err_name::err_name;
use crate::security::keyring_capsule::KeyringCapsuleError;
use crate::services::lifecycle::smoketest_log;

const TAG: &[u8] = b"[KEYRING-TEST] ";

pub(super) fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

pub(super) fn fail(stage: &[u8], err: KeyringCapsuleError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

pub(super) fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

pub(super) fn fail_false(reason: &[u8]) -> bool {
    fail_msg(reason);
    false
}

pub(super) fn fail_err_false(stage: &[u8], err: KeyringCapsuleError) -> bool {
    fail(stage, err);
    false
}
