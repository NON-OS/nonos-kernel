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

use super::save::{save_database, DATABASE};
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::InstalledPackage;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn register_package(pkg: InstalledPackage) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    for file in &pkg.files {
        if let Some(owner) = db.file_owners.get(file) {
            if owner != &pkg.meta.name {
                return Err(NpkgError::FileConflict(file.clone(), owner.clone()));
            }
        }
    }
    for file in &pkg.files {
        db.file_owners.insert(file.clone(), pkg.meta.name.clone());
    }
    db.packages.insert(pkg.meta.name.clone(), pkg);
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();
    drop(guard);
    save_database()
}

pub fn unregister_package(name: &str) -> NpkgResult<InstalledPackage> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let pkg =
        db.packages.remove(name).ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;
    for file in &pkg.files {
        db.file_owners.remove(file);
    }
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();
    drop(guard);
    save_database()?;
    Ok(pkg)
}
