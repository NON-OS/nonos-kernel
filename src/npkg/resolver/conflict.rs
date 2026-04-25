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

use super::super::database::is_installed;
use super::super::error::{NpkgError, NpkgResult};
use super::super::types::{DependencyKind, Package};
use alloc::collections::BTreeMap;

pub fn check_conflicts(packages: &[&Package]) -> NpkgResult<()> {
    let mut provides: BTreeMap<alloc::string::String, alloc::string::String> = BTreeMap::new();
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
