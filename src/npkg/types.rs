// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageId {
    pub name: String,
    pub version: PackageVersion,
}

impl PackageId {
    pub fn new(name: String, version: PackageVersion) -> Self {
        Self { name, version }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.rsplitn(2, '-').collect();
        if parts.len() == 2 {
            let version = PackageVersion::parse(parts[0])?;
            let name = String::from(parts[1]);
            Some(Self { name, version })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
    pub build: Option<String>,
}

impl PackageVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre_release: None,
            build: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (version_str, build) = if let Some(idx) = s.find('+') {
            (&s[..idx], Some(String::from(&s[idx + 1..])))
        } else {
            (s, None)
        };

        let (version_str, pre_release) = if let Some(idx) = version_str.find('-') {
            (&version_str[..idx], Some(String::from(&version_str[idx + 1..])))
        } else {
            (version_str, None)
        };

        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }

        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = if parts.len() == 3 {
            parts[2].parse().ok()?
        } else {
            0
        };

        Some(Self {
            major,
            minor,
            patch,
            pre_release,
            build,
        })
    }

    pub fn to_string(&self) -> String {
        let mut s = alloc::format!("{}.{}.{}", self.major, self.minor, self.patch);
        if let Some(ref pre) = self.pre_release {
            s.push('-');
            s.push_str(pre);
        }
        if let Some(ref build) = self.build {
            s.push('+');
            s.push_str(build);
        }
        s
    }

    pub fn satisfies(&self, requirement: &VersionRequirement) -> bool {
        match requirement {
            VersionRequirement::Exact(v) => self == v,
            VersionRequirement::GreaterThan(v) => self > v,
            VersionRequirement::GreaterOrEqual(v) => self >= v,
            VersionRequirement::LessThan(v) => self < v,
            VersionRequirement::LessOrEqual(v) => self <= v,
            VersionRequirement::Compatible(v) => {
                self.major == v.major && self >= v
            }
            VersionRequirement::Any => true,
        }
    }
}

impl PartialOrd for PackageVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match (&self.pre_release, &other.pre_release) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRequirement {
    Exact(PackageVersion),
    GreaterThan(PackageVersion),
    GreaterOrEqual(PackageVersion),
    LessThan(PackageVersion),
    LessOrEqual(PackageVersion),
    Compatible(PackageVersion),
    Any,
}

impl VersionRequirement {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "*" || s.is_empty() {
            return Some(Self::Any);
        }

        if let Some(rest) = s.strip_prefix(">=") {
            PackageVersion::parse(rest.trim()).map(Self::GreaterOrEqual)
        } else if let Some(rest) = s.strip_prefix("<=") {
            PackageVersion::parse(rest.trim()).map(Self::LessOrEqual)
        } else if let Some(rest) = s.strip_prefix('>') {
            PackageVersion::parse(rest.trim()).map(Self::GreaterThan)
        } else if let Some(rest) = s.strip_prefix('<') {
            PackageVersion::parse(rest.trim()).map(Self::LessThan)
        } else if let Some(rest) = s.strip_prefix('^') {
            PackageVersion::parse(rest.trim()).map(Self::Compatible)
        } else if let Some(rest) = s.strip_prefix('=') {
            PackageVersion::parse(rest.trim()).map(Self::Exact)
        } else {
            PackageVersion::parse(s).map(Self::Exact)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    X86_64,
    Aarch64,
    Any,
}

impl Architecture {
    pub fn current() -> Self {
        Architecture::X86_64
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            "any" | "noarch" => Some(Self::Any),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Any => "any",
        }
    }

    pub fn is_compatible(&self, target: Architecture) -> bool {
        match (self, target) {
            (Self::Any, _) => true,
            (a, b) => a == &b,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageKind {
    Binary,
    Library,
    Data,
    Font,
    Theme,
    Driver,
    Service,
    Meta,
}

impl PackageKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "binary" | "bin" => Some(Self::Binary),
            "library" | "lib" => Some(Self::Library),
            "data" => Some(Self::Data),
            "font" => Some(Self::Font),
            "theme" => Some(Self::Theme),
            "driver" => Some(Self::Driver),
            "service" => Some(Self::Service),
            "meta" => Some(Self::Meta),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Library => "library",
            Self::Data => "data",
            Self::Font => "font",
            Self::Theme => "theme",
            Self::Driver => "driver",
            Self::Service => "service",
            Self::Meta => "meta",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageState {
    Available,
    Downloading,
    Downloaded,
    Installing,
    Installed,
    Removing,
    Broken,
    OnHold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyKind {
    Runtime,
    Build,
    Optional,
    Conflict,
    Replace,
    Provide,
}

impl DependencyKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "runtime" | "depends" => Some(Self::Runtime),
            "build" | "makedepends" => Some(Self::Build),
            "optional" | "optdepends" => Some(Self::Optional),
            "conflict" | "conflicts" => Some(Self::Conflict),
            "replace" | "replaces" => Some(Self::Replace),
            "provide" | "provides" => Some(Self::Provide),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: VersionRequirement,
    pub kind: DependencyKind,
    pub reason: Option<String>,
}

impl Dependency {
    pub fn runtime(name: &str, version: VersionRequirement) -> Self {
        Self {
            name: String::from(name),
            version,
            kind: DependencyKind::Runtime,
            reason: None,
        }
    }

    pub fn optional(name: &str, reason: &str) -> Self {
        Self {
            name: String::from(name),
            version: VersionRequirement::Any,
            kind: DependencyKind::Optional,
            reason: Some(String::from(reason)),
        }
    }

    pub fn conflict(name: &str) -> Self {
        Self {
            name: String::from(name),
            version: VersionRequirement::Any,
            kind: DependencyKind::Conflict,
            reason: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let (name, version) = if let Some(idx) = s.find(|c: char| c == '>' || c == '<' || c == '=' || c == '^') {
            let name = s[..idx].trim();
            let version_str = &s[idx..];
            (name, VersionRequirement::parse(version_str)?)
        } else {
            (s, VersionRequirement::Any)
        };

        Some(Self {
            name: String::from(name),
            version,
            kind: DependencyKind::Runtime,
            reason: None,
        })
    }
}

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

#[derive(Debug, Clone)]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub checksum: [u8; 32],
    pub permissions: FilePermissions,
    pub is_config: bool,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct FilePermissions {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Default for FilePermissions {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }
}

impl FilePermissions {
    pub fn executable() -> Self {
        Self {
            mode: 0o755,
            uid: 0,
            gid: 0,
        }
    }

    pub fn directory() -> Self {
        Self {
            mode: 0o755,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub meta: PackageMeta,
    pub install_time: u64,
    pub install_reason: InstallReason,
    pub files: Vec<String>,
    pub state: PackageState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReason {
    Explicit,
    Dependency,
    Optional,
}
