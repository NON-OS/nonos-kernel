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

use super::types::Manifest;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::{
    Architecture, Dependency, Package, PackageFile, PackageKind, PackageMeta, PackageVersion,
};
use alloc::string::String;
use alloc::vec::Vec;

pub struct ManifestBuilder {
    name: Option<String>,
    version: Option<PackageVersion>,
    description: Option<String>,
    long_description: Option<String>,
    homepage: Option<String>,
    license: Option<String>,
    maintainer: Option<String>,
    architecture: Architecture,
    kind: PackageKind,
    dependencies: Vec<Dependency>,
    files: Vec<PackageFile>,
    install_script: Option<String>,
    remove_script: Option<String>,
}

impl ManifestBuilder {
    pub fn new() -> Self {
        Self {
            name: None,
            version: None,
            description: None,
            long_description: None,
            homepage: None,
            license: None,
            maintainer: None,
            architecture: Architecture::current(),
            kind: PackageKind::Binary,
            dependencies: Vec::new(),
            files: Vec::new(),
            install_script: None,
            remove_script: None,
        }
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(String::from(name));
        self
    }
    pub fn version(mut self, version: PackageVersion) -> Self {
        self.version = Some(version);
        self
    }
    pub fn description(mut self, desc: &str) -> Self {
        self.description = Some(String::from(desc));
        self
    }
    pub fn license(mut self, license: &str) -> Self {
        self.license = Some(String::from(license));
        self
    }
    pub fn architecture(mut self, arch: Architecture) -> Self {
        self.architecture = arch;
        self
    }
    pub fn kind(mut self, kind: PackageKind) -> Self {
        self.kind = kind;
        self
    }
    pub fn dependency(mut self, dep: Dependency) -> Self {
        self.dependencies.push(dep);
        self
    }
    pub fn file(mut self, file: PackageFile) -> Self {
        self.files.push(file);
        self
    }
    pub fn install_script(mut self, script: &str) -> Self {
        self.install_script = Some(String::from(script));
        self
    }
    pub fn remove_script(mut self, script: &str) -> Self {
        self.remove_script = Some(String::from(script));
        self
    }

    pub fn build(self) -> NpkgResult<Manifest> {
        let name =
            self.name.ok_or_else(|| NpkgError::ManifestParseError(String::from("missing name")))?;
        let version = self
            .version
            .ok_or_else(|| NpkgError::ManifestParseError(String::from("missing version")))?;
        let meta = PackageMeta {
            name,
            version,
            description: self.description.unwrap_or_default(),
            long_description: self.long_description,
            homepage: self.homepage,
            license: self.license.unwrap_or_else(|| String::from("AGPL-3.0")),
            maintainer: self.maintainer,
            architecture: self.architecture,
            kind: self.kind,
            size_installed: 0,
            size_download: 0,
            checksum_blake3: [0u8; 32],
            signature: None,
        };
        let package = Package {
            meta,
            dependencies: self.dependencies,
            files: self.files,
            install_script: self.install_script,
            remove_script: self.remove_script,
        };
        Ok(Manifest::new(package))
    }
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
