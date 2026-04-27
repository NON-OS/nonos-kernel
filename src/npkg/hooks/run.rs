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

use super::execute::execute_script;
use crate::npkg::error::NpkgResult;

pub fn run_pre_install(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }
    crate::info!("npkg: running pre-install script for {}", package);
    execute_script(package, script, "pre_install")
}

pub fn run_post_install(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }
    crate::info!("npkg: running post-install script for {}", package);
    execute_script(package, script, "post_install")
}

pub fn run_pre_remove(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }
    crate::info!("npkg: running pre-remove script for {}", package);
    execute_script(package, script, "pre_remove")
}

pub fn run_post_remove(package: &str, script: &str) -> NpkgResult<()> {
    if script.is_empty() {
        return Ok(());
    }
    crate::info!("npkg: running post-remove script for {}", package);
    execute_script(package, script, "post_remove")
}
