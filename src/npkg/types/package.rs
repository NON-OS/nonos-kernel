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

use super::architecture::Architecture;
use super::dependency::Dependency;
use super::file_types::PackageFile;
use super::package_id::PackageId;
use super::package_kind::PackageKind;
use super::version::PackageVersion;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct PackageMeta {
    pub name: String,
    pub version: PackageVersion,
    pub description: String,
    pub long_description: Option<String>,
    pub homepage: Option<String>,
    pub license: String,
    pub maintainer: Option<String>,
    pub architecture: Architecture,
    pub kind: PackageKind,
    pub size_installed: u64,
    pub size_download: u64,
    pub checksum_blake3: [u8; 32],
    pub signature: Option<[u8; 64]>,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub meta: PackageMeta,
    pub dependencies: Vec<Dependency>,
    pub files: Vec<PackageFile>,
    pub install_script: Option<String>,
    pub remove_script: Option<String>,
}

impl Package {
    pub fn id(&self) -> PackageId {
        PackageId::new(self.meta.name.clone(), self.meta.version.clone())
    }
}
