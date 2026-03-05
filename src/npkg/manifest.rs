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

use alloc::string::String;
use alloc::vec::Vec;
use super::types::{
    Package, PackageMeta, PackageVersion, PackageKind, Architecture,
    Dependency, DependencyKind, VersionRequirement, PackageFile, FilePermissions,
};
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct Manifest {
    pub package: Package,
    raw: Vec<u8>,
}

impl Manifest {
    pub fn new(package: Package) -> Self {
        Self {
            package,
            raw: Vec::new(),
        }
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
}

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
        let name = self.name.ok_or_else(|| NpkgError::ManifestParseError(String::from("missing name")))?;
        let version = self.version.ok_or_else(|| NpkgError::ManifestParseError(String::from("missing version")))?;
        let description = self.description.unwrap_or_default();
        let license = self.license.unwrap_or_else(|| String::from("AGPL-3.0"));

        let meta = PackageMeta {
            name,
            version,
            description,
            long_description: self.long_description,
            homepage: self.homepage,
            license,
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

pub fn parse_manifest(data: &[u8]) -> NpkgResult<Manifest> {
    let text = core::str::from_utf8(data)
        .map_err(|_| NpkgError::ManifestParseError(String::from("invalid UTF-8")))?;

    let mut name: Option<String> = None;
    let mut version: Option<PackageVersion> = None;
    let mut description: Option<String> = None;
    let mut long_description: Option<String> = None;
    let mut homepage: Option<String> = None;
    let mut license: Option<String> = None;
    let mut maintainer: Option<String> = None;
    let mut architecture = Architecture::Any;
    let mut kind = PackageKind::Binary;
    let mut dependencies: Vec<Dependency> = Vec::new();
    let mut files: Vec<PackageFile> = Vec::new();
    let mut install_script: Option<String> = None;
    let mut remove_script: Option<String> = None;

    let mut in_deps = false;
    let mut in_files = false;
    let mut in_install = false;
    let mut in_remove = false;
    let mut script_buf = String::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[dependencies]" {
            in_deps = true;
            in_files = false;
            in_install = false;
            in_remove = false;
            continue;
        }

        if line == "[files]" {
            in_deps = false;
            in_files = true;
            in_install = false;
            in_remove = false;
            continue;
        }

        if line == "[install]" {
            in_deps = false;
            in_files = false;
            in_install = true;
            in_remove = false;
            script_buf.clear();
            continue;
        }

        if line == "[remove]" {
            if in_install {
                install_script = Some(script_buf.clone());
            }
            in_deps = false;
            in_files = false;
            in_install = false;
            in_remove = true;
            script_buf.clear();
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if in_install {
                install_script = Some(script_buf.clone());
            }
            if in_remove {
                remove_script = Some(script_buf.clone());
            }
            in_deps = false;
            in_files = false;
            in_install = false;
            in_remove = false;
            continue;
        }

        if in_install || in_remove {
            script_buf.push_str(line);
            script_buf.push('\n');
            continue;
        }

        if in_deps {
            if let Some(dep) = parse_dependency_line(line) {
                dependencies.push(dep);
            }
            continue;
        }

        if in_files {
            if let Some(file) = parse_file_line(line) {
                files.push(file);
            }
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');

            match key {
                "name" => name = Some(String::from(value)),
                "version" => version = PackageVersion::parse(value),
                "description" => description = Some(String::from(value)),
                "long_description" => long_description = Some(String::from(value)),
                "homepage" => homepage = Some(String::from(value)),
                "license" => license = Some(String::from(value)),
                "maintainer" => maintainer = Some(String::from(value)),
                "architecture" | "arch" => {
                    if let Some(a) = Architecture::from_str(value) {
                        architecture = a;
                    }
                }
                "kind" | "type" => {
                    if let Some(k) = PackageKind::from_str(value) {
                        kind = k;
                    }
                }
                _ => {}
            }
        }
    }

    if in_install {
        install_script = Some(script_buf.clone());
    }
    if in_remove {
        remove_script = Some(script_buf);
    }

    let name = name.ok_or_else(|| NpkgError::ManifestParseError(String::from("missing name")))?;
    let version = version.ok_or_else(|| NpkgError::ManifestParseError(String::from("missing version")))?;

    let meta = PackageMeta {
        name,
        version,
        description: description.unwrap_or_default(),
        long_description,
        homepage,
        license: license.unwrap_or_else(|| String::from("AGPL-3.0")),
        maintainer,
        architecture,
        kind,
        size_installed: 0,
        size_download: 0,
        checksum_blake3: [0u8; 32],
        signature: None,
    };

    let package = Package {
        meta,
        dependencies,
        files,
        install_script,
        remove_script,
    };

    Ok(Manifest {
        package,
        raw: data.to_vec(),
    })
}

fn parse_dependency_line(line: &str) -> Option<Dependency> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut kind = DependencyKind::Runtime;
    let mut line = line;

    if let Some(rest) = line.strip_prefix("optional:") {
        kind = DependencyKind::Optional;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("conflict:") {
        kind = DependencyKind::Conflict;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("replace:") {
        kind = DependencyKind::Replace;
        line = rest.trim();
    } else if let Some(rest) = line.strip_prefix("provide:") {
        kind = DependencyKind::Provide;
        line = rest.trim();
    }

    let (name, version, reason) = if let Some((spec, reason)) = line.split_once(':') {
        let (name, version) = parse_name_version(spec.trim());
        (name, version, Some(String::from(reason.trim())))
    } else {
        let (name, version) = parse_name_version(line);
        (name, version, None)
    };

    Some(Dependency {
        name: String::from(name),
        version,
        kind,
        reason,
    })
}

fn parse_name_version(s: &str) -> (&str, VersionRequirement) {
    for (i, c) in s.char_indices() {
        if c == '>' || c == '<' || c == '=' || c == '^' {
            let name = s[..i].trim();
            let version = VersionRequirement::parse(&s[i..]).unwrap_or(VersionRequirement::Any);
            return (name, version);
        }
    }
    (s.trim(), VersionRequirement::Any)
}

fn parse_file_line(line: &str) -> Option<PackageFile> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let path = String::from(parts[0]);
    let mut permissions = FilePermissions::default();
    let mut is_config = false;
    let mut is_directory = path.ends_with('/');

    for part in parts.iter().skip(1) {
        if *part == "config" {
            is_config = true;
        } else if *part == "dir" {
            is_directory = true;
            permissions = FilePermissions::directory();
        } else if *part == "exec" {
            permissions = FilePermissions::executable();
        } else if let Ok(mode) = u32::from_str_radix(part, 8) {
            permissions.mode = mode;
        }
    }

    Some(PackageFile {
        path,
        size: 0,
        checksum: [0u8; 32],
        permissions,
        is_config,
        is_directory,
    })
}

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

    if !pkg.dependencies.is_empty() {
        out.push_str("\n[dependencies]\n");
        for dep in &pkg.dependencies {
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
                VersionRequirement::GreaterThan(v) => out.push_str(&alloc::format!(" > {}", v.to_string())),
                VersionRequirement::GreaterOrEqual(v) => out.push_str(&alloc::format!(" >= {}", v.to_string())),
                VersionRequirement::LessThan(v) => out.push_str(&alloc::format!(" < {}", v.to_string())),
                VersionRequirement::LessOrEqual(v) => out.push_str(&alloc::format!(" <= {}", v.to_string())),
                VersionRequirement::Compatible(v) => out.push_str(&alloc::format!(" ^{}", v.to_string())),
            }
            if let Some(ref reason) = dep.reason {
                out.push_str(&alloc::format!(": {}", reason));
            }
            out.push('\n');
        }
    }

    if !pkg.files.is_empty() {
        out.push_str("\n[files]\n");
        for file in &pkg.files {
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

    if let Some(ref script) = pkg.install_script {
        out.push_str("\n[install]\n");
        out.push_str(script);
        if !script.ends_with('\n') {
            out.push('\n');
        }
    }

    if let Some(ref script) = pkg.remove_script {
        out.push_str("\n[remove]\n");
        out.push_str(script);
        if !script.ends_with('\n') {
            out.push('\n');
        }
    }

    out.into_bytes()
}

const MANIFEST_CACHE_DIR: &str = "/var/lib/npkg/manifests";

pub fn cache_manifest(name: &str, manifest: &Manifest) -> NpkgResult<()> {
    let _ = crate::fs::mkdir(MANIFEST_CACHE_DIR, 0o755);
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let data = serialize_manifest(manifest);
    crate::fs::nonos_vfs::vfs_write_file(&path, &data)
        .map_err(|_| NpkgError::IoError(alloc::format!("failed to cache manifest: {}", name)))?;
    Ok(())
}

pub fn get_cached_manifest(name: &str) -> Option<Package> {
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let data = crate::fs::read_file_bytes(&path).ok()?;
    let manifest = parse_manifest(&data).ok()?;
    Some(manifest.package)
}

pub fn remove_cached_manifest(name: &str) -> NpkgResult<()> {
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let _ = crate::fs::unlink(&path);
    Ok(())
}
