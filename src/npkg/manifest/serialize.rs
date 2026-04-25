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
use crate::npkg::types::{DependencyKind, VersionRequirement};
use alloc::string::String;
use alloc::vec::Vec;

pub fn serialize_manifest(manifest: &Manifest) -> Vec<u8> {
    let pkg = &manifest.package;
    let mut out = String::new();
    out.push_str(&alloc::format!("name = \"{}\"\n", pkg.meta.name));
    out.push_str(&alloc::format!("version = \"{}\"\n", pkg.meta.version.to_string()));
    out.push_str(&alloc::format!("description = \"{}\"\n", pkg.meta.description));
    if let Some(ref long) = pkg.meta.long_description {
        out.push_str(&alloc::format!("long_description = \"{}\"\n", long));
    }
    if let Some(ref hp) = pkg.meta.homepage {
        out.push_str(&alloc::format!("homepage = \"{}\"\n", hp));
    }
    out.push_str(&alloc::format!("license = \"{}\"\n", pkg.meta.license));
    if let Some(ref maint) = pkg.meta.maintainer {
        out.push_str(&alloc::format!("maintainer = \"{}\"\n", maint));
    }
    out.push_str(&alloc::format!("architecture = \"{}\"\n", pkg.meta.architecture.as_str()));
    out.push_str(&alloc::format!("kind = \"{}\"\n", pkg.meta.kind.as_str()));
    serialize_dependencies(&pkg.dependencies, &mut out);
    serialize_files(&pkg.files, &mut out);
    serialize_scripts(&pkg.install_script, &pkg.remove_script, &mut out);
    out.into_bytes()
}

fn serialize_dependencies(deps: &[crate::npkg::types::Dependency], out: &mut String) {
    if deps.is_empty() {
        return;
    }
    out.push_str("\n[dependencies]\n");
    for dep in deps {
        let prefix = match dep.kind {
            DependencyKind::Runtime => "",
            DependencyKind::Optional => "optional: ",
            DependencyKind::Conflict => "conflict: ",
            DependencyKind::Replace => "replace: ",
            DependencyKind::Provide => "provide: ",
            DependencyKind::Build => "build: ",
        };
        out.push_str(prefix);
        out.push_str(&dep.name);
        match &dep.version {
            VersionRequirement::Any => {}
            VersionRequirement::Exact(v) => out.push_str(&alloc::format!(" = {}", v.to_string())),
            VersionRequirement::GreaterThan(v) => {
                out.push_str(&alloc::format!(" > {}", v.to_string()))
            }
            VersionRequirement::GreaterOrEqual(v) => {
                out.push_str(&alloc::format!(" >= {}", v.to_string()))
            }
            VersionRequirement::LessThan(v) => {
                out.push_str(&alloc::format!(" < {}", v.to_string()))
            }
            VersionRequirement::LessOrEqual(v) => {
                out.push_str(&alloc::format!(" <= {}", v.to_string()))
            }
            VersionRequirement::Compatible(v) => {
                out.push_str(&alloc::format!(" ^{}", v.to_string()))
            }
        }
        if let Some(ref reason) = dep.reason {
            out.push_str(&alloc::format!(": {}", reason));
        }
        out.push('\n');
    }
}

fn serialize_files(files: &[crate::npkg::types::PackageFile], out: &mut String) {
    if files.is_empty() {
        return;
    }
    out.push_str("\n[files]\n");
    for file in files {
        out.push_str(&file.path);
        if file.is_directory {
            out.push_str(" dir");
        } else if file.permissions.mode == 0o755 {
            out.push_str(" exec");
        } else if file.permissions.mode != 0o644 {
            out.push_str(&alloc::format!(" {:o}", file.permissions.mode));
        }
        if file.is_config {
            out.push_str(" config");
        }
        out.push('\n');
    }
}

fn serialize_scripts(install: &Option<String>, remove: &Option<String>, out: &mut String) {
    if let Some(ref script) = install {
        out.push_str("\n[install]\n");
        out.push_str(script);
        if !script.ends_with('\n') {
            out.push('\n');
        }
    }
    if let Some(ref script) = remove {
        out.push_str("\n[remove]\n");
        out.push_str(script);
        if !script.ends_with('\n') {
            out.push('\n');
        }
    }
}
