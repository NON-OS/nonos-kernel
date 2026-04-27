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

use super::install_single::install_single_package;
use super::options::{InstallOptions, RemoveOptions};
use super::remove::remove_package;
use crate::npkg::database::{is_installed, query_by_name};
use crate::npkg::download::download_package;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::resolver::{check_conflicts, resolve_dependencies, ResolutionResult};
use crate::npkg::types::{InstallReason, Package};
use alloc::string::String;
use alloc::vec::Vec;

pub fn install_package(name: &str, options: &InstallOptions) -> NpkgResult<()> {
    install_packages(&[name], options)
}

pub fn install_packages(names: &[&str], options: &InstallOptions) -> NpkgResult<()> {
    if !options.reinstall {
        for name in names {
            if is_installed(name) && !options.force {
                return Err(NpkgError::AlreadyInstalled(String::from(*name)));
            }
        }
    }
    let resolution = if options.no_deps {
        let mut result = ResolutionResult {
            to_install: Vec::new(),
            to_upgrade: Vec::new(),
            to_remove: Vec::new(),
            satisfied: Vec::new(),
            optional: Vec::new(),
        };
        for name in names {
            let pkg = crate::npkg::repository::find_package(name)
                .ok_or_else(|| NpkgError::PackageNotFound(String::from(*name)))?;
            let reason = if options.as_dependency {
                InstallReason::Dependency
            } else {
                InstallReason::Explicit
            };
            result.to_install.push((pkg, reason));
        }
        result
    } else {
        resolve_dependencies(names)?
    };
    let packages: Vec<&Package> = resolution.to_install.iter().map(|(p, _)| p).collect();
    check_conflicts(&packages)?;
    if options.download_only {
        for (pkg, _) in &resolution.to_install {
            let _ = download_package(pkg)?;
        }
        return Ok(());
    }
    for name in &resolution.to_remove {
        remove_package(name, &RemoveOptions::default())?;
    }
    for (pkg, reason) in resolution.to_install {
        install_single_package(&pkg, reason, options)?;
    }
    for (pkg, _old_version) in resolution.to_upgrade {
        let reason = query_by_name(&pkg.meta.name)
            .map(|p| p.install_reason)
            .unwrap_or(InstallReason::Explicit);
        install_single_package(&pkg, reason, options)?;
    }
    Ok(())
}
