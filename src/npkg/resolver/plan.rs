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

use super::super::database::query_by_name;
use super::super::error::{NpkgError, NpkgResult};
use super::types::{ResolutionPlan, ResolutionResult};

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
    ResolutionPlan { result, download_size, install_size, remove_size }
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
