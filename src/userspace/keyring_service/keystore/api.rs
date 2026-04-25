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

use super::storage::KEYRING;
use super::types::{KeyMetadata, KeyType};

pub(crate) fn store_key(
    key_type: KeyType,
    data: &[u8],
    owner_pid: u32,
    expires_at: u64,
) -> Option<u32> {
    KEYRING.lock().store(key_type, data, owner_pid, expires_at)
}

pub(crate) fn retrieve_key(id: u32, owner_pid: u32, output: &mut [u8]) -> Option<usize> {
    let (data, size) = KEYRING.lock().retrieve(id, owner_pid)?;
    if output.len() >= size {
        output[..size].copy_from_slice(&data[..size]);
        Some(size)
    } else {
        None
    }
}

pub(crate) fn delete_key(id: u32, owner_pid: u32) -> bool {
    KEYRING.lock().delete(id, owner_pid)
}

pub(crate) fn lock_key(id: u32, owner_pid: u32) -> bool {
    KEYRING.lock().lock(id, owner_pid)
}

pub(crate) fn unlock_key(id: u32, owner_pid: u32) -> bool {
    KEYRING.lock().unlock(id, owner_pid)
}

pub(crate) fn get_key_metadata(id: u32) -> Option<KeyMetadata> {
    KEYRING.lock().get_metadata(id)
}

pub(crate) fn key_count() -> usize {
    KEYRING.lock().count()
}

pub(crate) fn cleanup_expired_keys() {
    KEYRING.lock().cleanup_expired()
}
