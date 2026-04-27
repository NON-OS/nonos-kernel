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
use super::types::PackageDatabase;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::InstallReason;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub fn mark_explicit(name: &str) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let pkg =
        db.packages.get_mut(name).ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;
    pkg.install_reason = InstallReason::Explicit;
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();
    drop(guard);
    save_database()
}

pub fn mark_dependency(name: &str) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let pkg =
        db.packages.get_mut(name).ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;
    pkg.install_reason = InstallReason::Dependency;
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();
    drop(guard);
    save_database()
}

pub fn get_orphans() -> Vec<String> {
    let guard = DATABASE.read();
    let db = match guard.as_ref() {
        Some(db) => db,
        None => return Vec::new(),
    };
    let mut required: BTreeSet<String> = BTreeSet::new();
    for pkg in db.packages.values() {
        if pkg.install_reason == InstallReason::Explicit {
            collect_dependencies(db, &pkg.meta.name, &mut required);
        }
    }
    db.packages
        .keys()
        .filter(|name| !required.contains(*name))
        .filter(|name| {
            db.packages
                .get(*name)
                .map(|p| p.install_reason != InstallReason::Explicit)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn collect_dependencies(db: &PackageDatabase, name: &str, required: &mut BTreeSet<String>) {
    if required.contains(name) {
        return;
    }
    required.insert(String::from(name));
    if let Some(_pkg) = db.packages.get(name) {
        if let Some(manifest) = crate::npkg::manifest::get_cached_manifest(name) {
            for dep in manifest.dependencies {
                collect_dependencies(db, &dep.name, required);
            }
        }
    }
}

pub fn verify_database_integrity() -> NpkgResult<Vec<String>> {
    let guard = DATABASE.read();
    let db = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let mut issues = Vec::new();
    for (name, pkg) in &db.packages {
        for file in &pkg.files {
            if !file_exists(file) {
                issues.push(alloc::format!("{}: missing file {}", name, file));
            }
        }
    }
    for (file, owner) in &db.file_owners {
        if !db.packages.contains_key(owner) {
            issues.push(alloc::format!("orphan file entry: {} -> {}", file, owner));
        }
    }
    Ok(issues)
}

fn file_exists(path: &str) -> bool {
    crate::fs::vfs::get_vfs().map(|vfs| vfs.exists(path)).unwrap_or(false)
}
