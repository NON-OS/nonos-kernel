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

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub force: bool,
    pub no_deps: bool,
    pub no_scripts: bool,
    pub download_only: bool,
    pub as_dependency: bool,
    pub reinstall: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            force: false,
            no_deps: false,
            no_scripts: false,
            download_only: false,
            as_dependency: false,
            reinstall: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemoveOptions {
    pub recursive: bool,
    pub no_scripts: bool,
    pub keep_config: bool,
    pub purge: bool,
}

impl Default for RemoveOptions {
    fn default() -> Self {
        Self { recursive: false, no_scripts: false, keep_config: true, purge: false }
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeOptions {
    pub no_deps: bool,
    pub no_scripts: bool,
    pub download_only: bool,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self { no_deps: false, no_scripts: false, download_only: false }
    }
}
