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
use super::options::{InstallOptions, UpgradeOptions};
use crate::npkg::database::{is_installed, query_by_name};
use crate::npkg::download::download_package;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::resolver::{resolve_dependencies, ResolutionResult};
use crate::npkg::types::InstallReason;
use alloc::string::String;
use alloc::vec::Vec;

pub fn upgrade_package(name: &str, options: &UpgradeOptions) -> NpkgResult<()> {
    upgrade_packages(&[name], options)
}

pub fn upgrade_packages(names: &[&str], options: &UpgradeOptions) -> NpkgResult<()> {
    for name in names {
        if !is_installed(name) {
            return Err(NpkgError::NotInstalled(String::from(*name)));
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
            let current =
                query_by_name(name).ok_or_else(|| NpkgError::NotInstalled(String::from(*name)))?;
            let latest = crate::npkg::repository::find_package(name)
                .ok_or_else(|| NpkgError::PackageNotFound(String::from(*name)))?;
            if latest.meta.version > current.meta.version {
                result.to_upgrade.push((latest, current.meta.version));
            } else {
                result.satisfied.push(String::from(*name));
            }
        }
        result
    } else {
        resolve_dependencies(names)?
    };
    if resolution.to_upgrade.is_empty() && resolution.to_install.is_empty() {
        if !resolution.satisfied.is_empty() {
            return Err(NpkgError::UpgradeNotNeeded(resolution.satisfied[0].clone()));
        }
    }
    if options.download_only {
        for (pkg, _) in &resolution.to_upgrade {
            let _ = download_package(pkg)?;
        }
        return Ok(());
    }
    for (pkg, _old_version) in resolution.to_upgrade {
        let reason = query_by_name(&pkg.meta.name)
            .map(|p| p.install_reason)
            .unwrap_or(InstallReason::Explicit);
        let opts = InstallOptions {
            force: true,
            no_deps: true,
            no_scripts: options.no_scripts,
            download_only: false,
            as_dependency: reason == InstallReason::Dependency,
            reinstall: true,
        };
        install_single_package(&pkg, reason, &opts)?;
    }
    Ok(())
}

pub fn reinstall_package(name: &str) -> NpkgResult<()> {
    let options = InstallOptions { reinstall: true, force: true, ..Default::default() };
    crate::npkg::installer::install::install_package(name, &options)
}
