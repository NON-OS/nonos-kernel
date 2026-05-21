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

use super::log::{fail, fail_err_false, fail_false, mark};
use super::steps;
use crate::security::keyring_capsule::{client, KeyringCapsuleError};

pub fn run() {
    mark(b"capsule alive");
    let Some(id) = steps::create_key() else { return };
    if !steps::check_initial_read(id) || !check_lock_cycle(id) || !check_metadata_count(id) {
        return;
    }
    match client::delete(id) {
        Ok(()) => mark(b"delete ok"),
        Err(e) => return fail(b"delete", e),
    }
    if steps::check_delete_denial(id) {
        mark(b"PASS");
    }
}

fn check_lock_cycle(id: u32) -> bool {
    if let Err(e) = client::lock(id) {
        fail(b"lock", e);
        return false;
    }
    mark(b"lock ok");
    match client::retrieve(id) {
        Err(KeyringCapsuleError::Locked) => mark(b"retrieve-locked denied"),
        Ok(_) => return fail_false(b"retrieve-locked: must EBUSY"),
        Err(e) => return fail_err_false(b"retrieve-locked", e),
    }
    if let Err(e) = client::unlock(id) {
        fail(b"unlock", e);
        return false;
    }
    mark(b"unlock ok");
    steps::check_initial_read(id)
}

fn check_metadata_count(id: u32) -> bool {
    match client::metadata(id) {
        Ok(m) if m.id == id && !m.locked && m.use_count >= 2 => mark(b"metadata ok"),
        Ok(_) => return fail_false(b"metadata: field mismatch"),
        Err(e) => return fail_err_false(b"metadata", e),
    }
    match client::count() {
        Ok(n) if n >= 1 => {
            mark(b"count ok");
            true
        }
        Ok(_) => fail_false(b"count: expected >= 1"),
        Err(e) => fail_err_false(b"count", e),
    }
}
