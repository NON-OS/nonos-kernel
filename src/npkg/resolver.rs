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

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use super::types::{
    Package, PackageVersion, Dependency, DependencyKind,
    VersionRequirement, InstallReason,
};
use super::repository::find_package;
use super::database::{is_installed, get_installed_version, query_by_name};
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub to_install: Vec<(Package, InstallReason)>,
    pub to_upgrade: Vec<(Package, PackageVersion)>,
    pub to_remove: Vec<String>,
    pub satisfied: Vec<String>,
    pub optional: Vec<(String, String)>,
}

impl ResolutionResult {
    fn new() -> Self {
        Self {
            to_install: Vec::new(),
            to_upgrade: Vec::new(),
            to_remove: Vec::new(),
            satisfied: Vec::new(),
            optional: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.to_install.is_empty() && self.to_upgrade.is_empty() && self.to_remove.is_empty()
    }

    pub fn total_packages(&self) -> usize {
        self.to_install.len() + self.to_upgrade.len()
    }
}

#[derive(Debug, Clone)]
pub struct ResolutionPlan {
    pub result: ResolutionResult,
    pub download_size: u64,
    pub install_size: u64,
    pub remove_size: u64,
}

pub struct DependencyResolver {
    visited: BTreeSet<String>,
    resolved: BTreeMap<String, Package>,
    resolution_stack: Vec<String>,
    optional_deps: Vec<(String, String)>,
}

impl DependencyResolver {
    pub fn new() -> Self {
        Self {
            visited: BTreeSet::new(),
            resolved: BTreeMap::new(),
            resolution_stack: Vec::new(),
            optional_deps: Vec::new(),
        }
    }

    pub fn resolve(&mut self, packages: &[&str]) -> NpkgResult<ResolutionResult> {
        let mut result = ResolutionResult::new();

        for name in packages {
            self.resolve_package(name, InstallReason::Explicit, &mut result)?;
        }

        result.optional = self.optional_deps.clone();
        self.sort_by_dependency_order(&mut result);

        Ok(result)
    }

    fn resolve_package(
        &mut self,
        name: &str,
        reason: InstallReason,
        result: &mut ResolutionResult,
    ) -> NpkgResult<()> {
        if self.visited.contains(name) {
            return Ok(());
        }

        if self.resolution_stack.contains(&String::from(name)) {
            let cycle = self.resolution_stack.join(" -> ");
            return Err(NpkgError::CircularDependency(alloc::format!("{} -> {}", cycle, name)));
        }

        self.resolution_stack.push(String::from(name));

        let pkg = find_package(name)
            .ok_or_else(|| NpkgError::PackageNotFound(String::from(name)))?;

        if let Some(installed_version) = get_installed_version(name) {
            if installed_version >= pkg.meta.version {
                result.satisfied.push(String::from(name));
                self.visited.insert(String::from(name));
                self.resolution_stack.pop();
                return Ok(());
            } else {
                result.to_upgrade.push((pkg.clone(), installed_version));
            }
        } else {
            result.to_install.push((pkg.clone(), reason));
        }

        for dep in &pkg.dependencies {
            match dep.kind {
                DependencyKind::Runtime => {
                    self.resolve_dependency(dep, result)?;
                }
                DependencyKind::Optional => {
                    let reason = dep.reason.clone().unwrap_or_default();
                    self.optional_deps.push((dep.name.clone(), reason));
                }
                DependencyKind::Conflict => {
                    if is_installed(&dep.name) {
                        return Err(NpkgError::DependencyConflict(
                            pkg.meta.name.clone(),
                            dep.name.clone(),
                        ));
                    }
                }
                DependencyKind::Replace => {
                    if is_installed(&dep.name) && !result.to_remove.contains(&dep.name) {
                        result.to_remove.push(dep.name.clone());
                    }
                }
                _ => {}
            }
        }

        self.visited.insert(String::from(name));
        self.resolved.insert(String::from(name), pkg);
        self.resolution_stack.pop();

        Ok(())
    }

    fn resolve_dependency(
        &mut self,
        dep: &Dependency,
        result: &mut ResolutionResult,
    ) -> NpkgResult<()> {
        if self.visited.contains(&dep.name) {
            return Ok(());
        }

        if let Some(installed_version) = get_installed_version(&dep.name) {
            if dep.version.satisfies_version(&installed_version) {
                result.satisfied.push(dep.name.clone());
                self.visited.insert(dep.name.clone());
                return Ok(());
            }
        }

        self.resolve_package(&dep.name, InstallReason::Dependency, result)
    }

    fn sort_by_dependency_order(&self, result: &mut ResolutionResult) {
        let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();

        for (pkg, _) in &result.to_install {
            let name = &pkg.meta.name;
            graph.entry(name.clone()).or_insert_with(Vec::new);
            in_degree.entry(name.clone()).or_insert(0);

            for dep in &pkg.dependencies {
                if dep.kind == DependencyKind::Runtime {
                    if result.to_install.iter().any(|(p, _)| p.meta.name == dep.name) {
                        graph.entry(dep.name.clone()).or_insert_with(Vec::new).push(name.clone());
                        *in_degree.entry(name.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut queue: VecDeque<String> = in_degree.iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(name, _)| name.clone())
            .collect();

        let mut sorted_names: Vec<String> = Vec::new();

        while let Some(name) = queue.pop_front() {
            sorted_names.push(name.clone());

            if let Some(dependents) = graph.get(&name) {
                for dependent in dependents {
                    if let Some(deg) = in_degree.get_mut(dependent) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(dependent.clone());
                        }
                    }
                }
            }
        }

        let mut sorted_install = Vec::with_capacity(result.to_install.len());
        for name in &sorted_names {
            if let Some(pos) = result.to_install.iter().position(|(p, _)| &p.meta.name == name) {
                sorted_install.push(result.to_install.remove(pos));
            }
        }

        for item in result.to_install.drain(..) {
            sorted_install.push(item);
        }

        result.to_install = sorted_install;
    }
}

impl Default for DependencyResolver {
    fn default() -> Self {
        Self::new()
    }
}

trait VersionCheck {
    fn satisfies_version(&self, version: &PackageVersion) -> bool;
}

impl VersionCheck for VersionRequirement {
    fn satisfies_version(&self, version: &PackageVersion) -> bool {
        version.satisfies(self)
    }
}

pub fn resolve_dependencies(packages: &[&str]) -> NpkgResult<ResolutionResult> {
    let mut resolver = DependencyResolver::new();
    resolver.resolve(packages)
}

pub fn check_conflicts(packages: &[&Package]) -> NpkgResult<()> {
    let mut provides: BTreeMap<String, String> = BTreeMap::new();

    for pkg in packages {
        for dep in &pkg.dependencies {
            if dep.kind == DependencyKind::Provide {
                if let Some(existing) = provides.get(&dep.name) {
                    return Err(NpkgError::DependencyConflict(
                        existing.clone(),
                        pkg.meta.name.clone(),
                    ));
                }
                provides.insert(dep.name.clone(), pkg.meta.name.clone());
            }
        }
    }

    for pkg in packages {
        for dep in &pkg.dependencies {
            if dep.kind == DependencyKind::Conflict {
                for other in packages {
                    if other.meta.name == dep.name {
                        return Err(NpkgError::DependencyConflict(
                            pkg.meta.name.clone(),
                            dep.name.clone(),
                        ));
                    }
                }

                if is_installed(&dep.name) {
                    return Err(NpkgError::DependencyConflict(
                        pkg.meta.name.clone(),
                        dep.name.clone(),
                    ));
                }
            }
        }
    }

    Ok(())
}

pub fn calculate_plan(result: ResolutionResult) -> ResolutionPlan {
    let mut download_size = 0u64;
    let mut install_size = 0u64;
    let mut remove_size = 0u64;

    for (pkg, _) in &result.to_install {
        download_size += pkg.meta.size_download;
        install_size += pkg.meta.size_installed;
    }

    for (pkg, _) in &result.to_upgrade {
        download_size += pkg.meta.size_download;
        install_size += pkg.meta.size_installed;
    }

    for name in &result.to_remove {
        if let Some(installed) = query_by_name(name) {
            remove_size += installed.meta.size_installed;
        }
    }

    ResolutionPlan {
        result,
        download_size,
        install_size,
        remove_size,
    }
}

pub fn check_system_requirements(plan: &ResolutionPlan) -> NpkgResult<()> {
    let stats = crate::fs::get_storage_stats();
    let available = stats.available_bytes as u64;

    let required = plan.install_size.saturating_sub(plan.remove_size);

    if available < required + (10 * 1024 * 1024) {
        return Err(NpkgError::DiskFull);
    }

    Ok(())
}
