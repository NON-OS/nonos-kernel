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
use crate::npkg::database::query_by_name;
use crate::npkg::download::download_package;
use crate::npkg::error::NpkgResult;
use crate::npkg::resolver::resolve_dependencies;
use crate::npkg::types::InstallReason;
use alloc::vec::Vec;

pub fn upgrade_all(options: &UpgradeOptions) -> NpkgResult<usize> {
    let installed = crate::npkg::database::query_installed();
    let names: Vec<&str> = installed.iter().map(|p| p.meta.name.as_str()).collect();
    if names.is_empty() {
        return Ok(0);
    }
    let resolution = resolve_dependencies(&names)?;
    let count = resolution.to_upgrade.len();
    if count == 0 {
        return Ok(0);
    }
    if options.download_only {
        for (pkg, _) in &resolution.to_upgrade {
            let _ = download_package(pkg)?;
        }
        return Ok(count);
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
    Ok(count)
}
