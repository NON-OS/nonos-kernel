// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::types::RepositoryConfig;
use crate::npkg::types::{Package, PackageVersion};
use alloc::{collections::BTreeMap, string::String, vec::Vec};

#[derive(Debug, Clone)]
pub struct Repository {
    pub config: RepositoryConfig,
    pub packages: BTreeMap<String, Vec<Package>>,
    pub last_sync: u64,
    pub package_count: usize,
}

impl Repository {
    pub fn new(config: RepositoryConfig) -> Self {
        Self { config, packages: BTreeMap::new(), last_sync: 0, package_count: 0 }
    }

    pub fn find_package(&self, name: &str) -> Option<&Package> {
        self.packages
            .get(name)
            .and_then(|versions| versions.iter().max_by(|a, b| a.meta.version.cmp(&b.meta.version)))
    }

    pub fn find_package_version(&self, name: &str, version: &PackageVersion) -> Option<&Package> {
        self.packages
            .get(name)
            .and_then(|versions| versions.iter().find(|p| &p.meta.version == version))
    }

    pub fn list_versions(&self, name: &str) -> Vec<&PackageVersion> {
        self.packages
            .get(name)
            .map(|versions| versions.iter().map(|p| &p.meta.version).collect())
            .unwrap_or_default()
    }

    pub fn search(&self, query: &str) -> Vec<&Package> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        for versions in self.packages.values() {
            if let Some(pkg) = versions.iter().max_by(|a, b| a.meta.version.cmp(&b.meta.version)) {
                if pkg.meta.name.to_lowercase().contains(&query_lower)
                    || pkg.meta.description.to_lowercase().contains(&query_lower)
                {
                    results.push(pkg);
                }
            }
        }
        results
    }
}
