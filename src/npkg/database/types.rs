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

use crate::npkg::types::{InstallReason, InstalledPackage};
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::AtomicBool;

#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_packages: u64,
    pub explicit_packages: u64,
    pub dependency_packages: u64,
    pub total_files: u64,
    pub total_size: u64,
    pub last_modified: u64,
}

pub struct PackageDatabase {
    pub(super) packages: BTreeMap<String, InstalledPackage>,
    pub(super) file_owners: BTreeMap<String, String>,
    pub(super) stats: DatabaseStats,
    pub(super) dirty: AtomicBool,
}

impl PackageDatabase {
    pub(super) fn new() -> Self {
        Self {
            packages: BTreeMap::new(),
            file_owners: BTreeMap::new(),
            stats: DatabaseStats {
                total_packages: 0,
                explicit_packages: 0,
                dependency_packages: 0,
                total_files: 0,
                total_size: 0,
                last_modified: 0,
            },
            dirty: AtomicBool::new(false),
        }
    }

    pub(super) fn recalculate_stats(&mut self) {
        let mut explicit = 0u64;
        let mut dependency = 0u64;
        let mut files = 0u64;
        let mut size = 0u64;
        for pkg in self.packages.values() {
            match pkg.install_reason {
                InstallReason::Explicit => explicit += 1,
                InstallReason::Dependency | InstallReason::Optional => dependency += 1,
            }
            files += pkg.files.len() as u64;
            size += pkg.meta.size_installed;
        }
        self.stats.total_packages = self.packages.len() as u64;
        self.stats.explicit_packages = explicit;
        self.stats.dependency_packages = dependency;
        self.stats.total_files = files;
        self.stats.total_size = size;
        self.stats.last_modified = crate::time::unix_timestamp();
    }
}
