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

use super::log::{fail, fail_msg, mark};
use crate::security::keyring_capsule::{client, KeyType, KeyringCapsuleError};

pub(super) const TEST_DATA: &[u8] = b"keyring smoketest payload bytes";

pub(super) fn create_key() -> Option<u32> {
    match client::store(KeyType::Symmetric, TEST_DATA, 0) {
        Ok(id) => {
            mark(b"store ok");
            Some(id)
        }
        Err(e) => {
            fail(b"store", e);
            None
        }
    }
}

pub(super) fn check_initial_read(id: u32) -> bool {
    match client::retrieve(id) {
        Ok(bytes) if bytes == TEST_DATA => {
            mark(b"retrieve ok");
            true
        }
        Ok(_) => {
            fail_msg(b"retrieve: byte mismatch");
            false
        }
        Err(e) => {
            fail(b"retrieve", e);
            false
        }
    }
}

pub(super) fn check_delete_denial(id: u32) -> bool {
    match client::retrieve(id) {
        Err(KeyringCapsuleError::NotFound) => {
            mark(b"retrieve-after-delete denied");
            true
        }
        Ok(_) => {
            fail_msg(b"retrieve-after-delete: must ENOENT");
            false
        }
        Err(e) => {
            fail(b"retrieve-after-delete", e);
            false
        }
    }
}
