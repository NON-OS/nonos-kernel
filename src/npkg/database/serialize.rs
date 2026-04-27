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

use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::{
    Architecture, InstallReason, InstalledPackage, PackageKind, PackageMeta, PackageState,
    PackageVersion,
};
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn deserialize_package(data: &[u8]) -> NpkgResult<InstalledPackage> {
    let text = core::str::from_utf8(data).map_err(|_| NpkgError::DatabaseCorrupt)?;
    let mut name: Option<String> = None;
    let mut version: Option<PackageVersion> = None;
    let mut description = String::new();
    let mut license = String::from("AGPL-3.0");
    let mut architecture = Architecture::Any;
    let mut kind = PackageKind::Binary;
    let mut size: u64 = 0;
    let mut install_time: u64 = 0;
    let mut install_reason = InstallReason::Explicit;
    let mut files: Vec<String> = Vec::new();
    let mut in_files = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "[files]" {
            in_files = true;
            continue;
        }
        if line.starts_with('[') {
            in_files = false;
            continue;
        }
        if in_files {
            if !line.is_empty() {
                files.push(String::from(line));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "name" => name = Some(String::from(value)),
                "version" => version = PackageVersion::parse(value),
                "description" => description = String::from(value),
                "license" => license = String::from(value),
                "arch" => architecture = Architecture::from_str(value).unwrap_or(Architecture::Any),
                "kind" => kind = PackageKind::from_str(value).unwrap_or(PackageKind::Binary),
                "size" => size = value.parse().unwrap_or(0),
                "install_time" => install_time = value.parse().unwrap_or(0),
                "reason" => {
                    install_reason = match value {
                        "explicit" => InstallReason::Explicit,
                        "dependency" => InstallReason::Dependency,
                        "optional" => InstallReason::Optional,
                        _ => InstallReason::Explicit,
                    }
                }
                _ => {}
            }
        }
    }
    let name = name.ok_or(NpkgError::DatabaseCorrupt)?;
    let version = version.ok_or(NpkgError::DatabaseCorrupt)?;
    let meta = PackageMeta {
        name,
        version,
        description,
        long_description: None,
        homepage: None,
        license,
        maintainer: None,
        architecture,
        kind,
        size_installed: size,
        size_download: 0,
        checksum_blake3: [0u8; 32],
        signature: None,
    };
    Ok(InstalledPackage {
        meta,
        install_time,
        install_reason,
        files,
        state: PackageState::Installed,
    })
}

pub(super) fn serialize_package(pkg: &InstalledPackage) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&alloc::format!("name = \"{}\"\n", pkg.meta.name));
    out.push_str(&alloc::format!("version = \"{}\"\n", pkg.meta.version.to_string()));
    out.push_str(&alloc::format!("description = \"{}\"\n", pkg.meta.description));
    out.push_str(&alloc::format!("license = \"{}\"\n", pkg.meta.license));
    out.push_str(&alloc::format!("arch = \"{}\"\n", pkg.meta.architecture.as_str()));
    out.push_str(&alloc::format!("kind = \"{}\"\n", pkg.meta.kind.as_str()));
    out.push_str(&alloc::format!("size = \"{}\"\n", pkg.meta.size_installed));
    out.push_str(&alloc::format!("install_time = \"{}\"\n", pkg.install_time));
    let reason = match pkg.install_reason {
        InstallReason::Explicit => "explicit",
        InstallReason::Dependency => "dependency",
        InstallReason::Optional => "optional",
    };
    out.push_str(&alloc::format!("reason = \"{}\"\n", reason));
    if !pkg.files.is_empty() {
        out.push_str("\n[files]\n");
        for file in &pkg.files {
            out.push_str(file);
            out.push('\n');
        }
    }
    out.into_bytes()
}
