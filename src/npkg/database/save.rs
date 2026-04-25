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

use super::serialize::serialize_package;
use super::types::PackageDatabase;
use crate::npkg::error::{NpkgError, NpkgResult};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

pub(super) const DB_PATH: &str = "/var/lib/npkg/db";
pub(super) const DB_VERSION: u32 = 1;
pub(super) static DATABASE: RwLock<Option<PackageDatabase>> = RwLock::new(None);
pub(super) static DB_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn save_database() -> NpkgResult<()> {
    let guard = DATABASE.read();
    let db = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    if !db.dirty.load(Ordering::SeqCst) {
        return Ok(());
    }
    let mut data = Vec::new();
    data.extend_from_slice(&0x4E504B47u32.to_le_bytes());
    data.extend_from_slice(&DB_VERSION.to_le_bytes());
    for pkg in db.packages.values() {
        let entry = serialize_package(pkg);
        data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        data.extend_from_slice(&entry);
    }
    drop(guard);
    crate::fs::nonos_vfs::vfs_write_file(DB_PATH, &data)
        .map_err(|_| NpkgError::IoError(String::from("failed to save database")))?;
    let guard = DATABASE.read();
    if let Some(db) = guard.as_ref() {
        db.dirty.store(false, Ordering::SeqCst);
    }
    Ok(())
}

pub fn get_database() -> Option<&'static RwLock<Option<PackageDatabase>>> {
    if DB_INITIALIZED.load(Ordering::SeqCst) {
        Some(&DATABASE)
    } else {
        None
    }
}
