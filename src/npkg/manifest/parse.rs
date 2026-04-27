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

use super::parse_helpers::{parse_dependency_line, parse_file_line};
use super::types::Manifest;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::{
    Architecture, Dependency, Package, PackageFile, PackageKind, PackageMeta, PackageVersion,
};
use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_manifest(data: &[u8]) -> NpkgResult<Manifest> {
    let text = core::str::from_utf8(data)
        .map_err(|_| NpkgError::ManifestParseError(String::from("invalid UTF-8")))?;
    let mut state = ParseState::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        state.process_line(line);
    }
    state.finalize(data)
}

#[derive(Default)]
struct ParseState {
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
    in_deps: bool,
    in_files: bool,
    in_install: bool,
    in_remove: bool,
    script_buf: String,
}

impl ParseState {
    fn process_line(&mut self, line: &str) {
        if self.handle_section(line) {
            return;
        }
        if self.in_install || self.in_remove {
            self.script_buf.push_str(line);
            self.script_buf.push('\n');
            return;
        }
        if self.in_deps {
            if let Some(dep) = parse_dependency_line(line) {
                self.dependencies.push(dep);
            }
            return;
        }
        if self.in_files {
            if let Some(file) = parse_file_line(line) {
                self.files.push(file);
            }
            return;
        }
        self.parse_field(line);
    }

    fn handle_section(&mut self, line: &str) -> bool {
        match line {
            "[dependencies]" => {
                self.reset_sections();
                self.in_deps = true;
                true
            }
            "[files]" => {
                self.reset_sections();
                self.in_files = true;
                true
            }
            "[install]" => {
                self.reset_sections();
                self.in_install = true;
                self.script_buf.clear();
                true
            }
            "[remove]" => {
                self.save_install();
                self.reset_sections();
                self.in_remove = true;
                self.script_buf.clear();
                true
            }
            s if s.starts_with('[') && s.ends_with(']') => {
                self.save_scripts();
                self.reset_sections();
                true
            }
            _ => false,
        }
    }

    fn reset_sections(&mut self) {
        self.in_deps = false;
        self.in_files = false;
        self.in_install = false;
        self.in_remove = false;
    }
    fn save_install(&mut self) {
        if self.in_install {
            self.install_script = Some(self.script_buf.clone());
        }
    }
    fn save_scripts(&mut self) {
        self.save_install();
        if self.in_remove {
            self.remove_script = Some(self.script_buf.clone());
        }
    }

    fn parse_field(&mut self, line: &str) {
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "name" => self.name = Some(String::from(value)),
                "version" => self.version = PackageVersion::parse(value),
                "description" => self.description = Some(String::from(value)),
                "long_description" => self.long_description = Some(String::from(value)),
                "homepage" => self.homepage = Some(String::from(value)),
                "license" => self.license = Some(String::from(value)),
                "maintainer" => self.maintainer = Some(String::from(value)),
                "architecture" | "arch" => {
                    if let Some(a) = Architecture::from_str(value) {
                        self.architecture = a;
                    }
                }
                "kind" | "type" => {
                    if let Some(k) = PackageKind::from_str(value) {
                        self.kind = k;
                    }
                }
                _ => {}
            }
        }
    }

    fn finalize(mut self, data: &[u8]) -> NpkgResult<Manifest> {
        self.save_scripts();
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
        Ok(Manifest { package, raw: data.to_vec() })
    }
}
