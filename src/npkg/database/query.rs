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

use super::save::DATABASE;
use super::types::DatabaseStats;
use crate::npkg::types::{InstalledPackage, PackageVersion};
use alloc::string::String;
use alloc::vec::Vec;

pub fn query_installed() -> Vec<InstalledPackage> {
    let guard = DATABASE.read();
    guard.as_ref().map(|db| db.packages.values().cloned().collect()).unwrap_or_default()
}

pub fn query_by_name(name: &str) -> Option<InstalledPackage> {
    let guard = DATABASE.read();
    guard.as_ref().and_then(|db| db.packages.get(name).cloned())
}

pub fn query_by_file(path: &str) -> Option<String> {
    let guard = DATABASE.read();
    guard.as_ref().and_then(|db| db.file_owners.get(path).cloned())
}

pub fn is_installed(name: &str) -> bool {
    let guard = DATABASE.read();
    guard.as_ref().map(|db| db.packages.contains_key(name)).unwrap_or(false)
}

pub fn get_installed_version(name: &str) -> Option<PackageVersion> {
    let guard = DATABASE.read();
    guard.as_ref().and_then(|db| db.packages.get(name)).map(|pkg| pkg.meta.version.clone())
}

pub fn get_database_stats() -> Option<DatabaseStats> {
    let guard = DATABASE.read();
    guard.as_ref().map(|db| db.stats.clone())
}
