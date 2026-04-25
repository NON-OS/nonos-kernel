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
use super::manager::REPO_MANAGER;
use crate::npkg::types::{Architecture, Package, PackageVersion};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

pub fn find_package(name: &str) -> Option<Package> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;
    let mut best: Option<(&Package, u32)> = None;
    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }
        if let Some(pkg) = repo.find_package(name) {
            let priority = repo.config.priority;
            match best {
                None => best = Some((pkg, priority)),
                Some((current, cur_pri)) => {
                    if priority > cur_pri
                        || (priority == cur_pri && pkg.meta.version > current.meta.version)
                    {
                        best = Some((pkg, priority));
                    }
                }
            }
        }
    }
    best.map(|(p, _)| p.clone())
}

pub fn find_package_version(name: &str, version: &PackageVersion) -> Option<Package> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;
    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }
        if let Some(pkg) = repo.find_package_version(name, version) {
            return Some(pkg.clone());
        }
    }
    None
}

pub fn search_packages(query: &str) -> Vec<Package> {
    let guard = REPO_MANAGER.read();
    let manager = match guard.as_ref() {
        Some(m) => m,
        None => return Vec::new(),
    };
    let mut results: BTreeMap<String, Package> = BTreeMap::new();
    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }
        for pkg in repo.search(query) {
            let name = &pkg.meta.name;
            if !results.contains_key(name) {
                results.insert(name.clone(), pkg.clone());
            }
        }
    }
    results.into_values().collect()
}

pub fn get_package_url(name: &str, version: &PackageVersion, arch: Architecture) -> Option<String> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;
    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }
        if repo.find_package_version(name, version).is_some() {
            return Some(format!(
                "{}/packages/{}-{}-{}.npkg",
                repo.config.url,
                name,
                version.to_string(),
                arch.as_str()
            ));
        }
    }
    None
}
