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

use super::super::types::{InstallReason, Package, PackageVersion};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub to_install: Vec<(Package, InstallReason)>,
    pub to_upgrade: Vec<(Package, PackageVersion)>,
    pub to_remove: Vec<String>,
    pub satisfied: Vec<String>,
    pub optional: Vec<(String, String)>,
}

impl ResolutionResult {
    pub fn new() -> Self {
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
