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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;
use super::types::{
    InstalledPackage, PackageMeta, PackageVersion, PackageState, InstallReason,
    Architecture, PackageKind,
};
use super::error::{NpkgError, NpkgResult};

const DB_PATH: &str = "/var/lib/npkg/db";
const DB_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_packages: u64,
    pub explicit_packages: u64,
    pub dependency_packages: u64,
    pub total_files: u64,
    pub total_size: u64,
    pub last_modified: u64,
}

pub struct PackageDatabase {
    packages: BTreeMap<String, InstalledPackage>,
    file_owners: BTreeMap<String, String>,
    stats: DatabaseStats,
    dirty: AtomicBool,
}

impl PackageDatabase {
    fn new() -> Self {
        Self {
            packages: BTreeMap::new(),
            file_owners: BTreeMap::new(),
            stats: DatabaseStats {
                total_packages: 0,
                explicit_packages: 0,
                dependency_packages: 0,
                total_files: 0,
                total_size: 0,
                last_modified: 0,
            },
            dirty: AtomicBool::new(false),
        }
    }

    fn recalculate_stats(&mut self) {
        let mut explicit = 0u64;
        let mut dependency = 0u64;
        let mut files = 0u64;
        let mut size = 0u64;

        for pkg in self.packages.values() {
            match pkg.install_reason {
                InstallReason::Explicit => explicit += 1,
                InstallReason::Dependency | InstallReason::Optional => dependency += 1,
            }
            files += pkg.files.len() as u64;
            size += pkg.meta.size_installed;
        }

        self.stats.total_packages = self.packages.len() as u64;
        self.stats.explicit_packages = explicit;
        self.stats.dependency_packages = dependency;
        self.stats.total_files = files;
        self.stats.total_size = size;
        self.stats.last_modified = crate::time::unix_timestamp();
    }
}

static DATABASE: RwLock<Option<PackageDatabase>> = RwLock::new(None);
static DB_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_database() -> NpkgResult<()> {
    if DB_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let _ = crate::fs::mkdir("/var", 0o755);
    let _ = crate::fs::mkdir("/var/lib", 0o755);
    let _ = crate::fs::mkdir("/var/lib/npkg", 0o755);

    let mut db = PackageDatabase::new();

    if let Ok(data) = crate::fs::read_file_bytes(DB_PATH) {
        load_database(&mut db, &data)?;
    }

    let mut guard = DATABASE.write();
    *guard = Some(db);

    Ok(())
}

fn load_database(db: &mut PackageDatabase, data: &[u8]) -> NpkgResult<()> {
    if data.len() < 8 {
        return Err(NpkgError::DatabaseCorrupt);
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x4E504B47 {
        return Err(NpkgError::DatabaseCorrupt);
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != DB_VERSION {
        return Err(NpkgError::DatabaseCorrupt);
    }

    let mut offset = 8;

    while offset + 4 <= data.len() {
        let entry_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        offset += 4;

        if offset + entry_len > data.len() {
            break;
        }

        if let Ok(pkg) = deserialize_package(&data[offset..offset + entry_len]) {
            for file in &pkg.files {
                db.file_owners.insert(file.clone(), pkg.meta.name.clone());
            }
            db.packages.insert(pkg.meta.name.clone(), pkg);
        }

        offset += entry_len;
    }

    db.recalculate_stats();
    Ok(())
}

fn deserialize_package(data: &[u8]) -> NpkgResult<InstalledPackage> {
    let text = core::str::from_utf8(data)
        .map_err(|_| NpkgError::DatabaseCorrupt)?;

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
                    };
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

fn serialize_package(pkg: &InstalledPackage) -> Vec<u8> {
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

pub fn save_database() -> NpkgResult<()> {
    let guard = DATABASE.read();
    let db = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    if !db.dirty.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut data = Vec::new();

    data.extend_from_slice(&0x4E504B47u32.to_le_bytes());
    data.extend_from_slice(&DB_VERSION.to_le_bytes());

    for pkg in db.packages.values() {
        let entry = serialize_package(pkg);
        data.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        data.extend_from_slice(&entry);
    }

    drop(guard);

    crate::fs::nonos_vfs::vfs_write_file(DB_PATH, &data)
        .map_err(|_| NpkgError::IoError(String::from("failed to save database")))?;

    let guard = DATABASE.read();
    if let Some(db) = guard.as_ref() {
        db.dirty.store(false, Ordering::SeqCst);
    }

    Ok(())
}

pub fn get_database() -> Option<&'static RwLock<Option<PackageDatabase>>> {
    if DB_INITIALIZED.load(Ordering::SeqCst) {
        Some(&DATABASE)
    } else {
        None
    }
}

pub fn register_package(pkg: InstalledPackage) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    for file in &pkg.files {
        if let Some(owner) = db.file_owners.get(file) {
            if owner != &pkg.meta.name {
                return Err(NpkgError::FileConflict(file.clone(), owner.clone()));
            }
        }
    }

    for file in &pkg.files {
        db.file_owners.insert(file.clone(), pkg.meta.name.clone());
    }

    db.packages.insert(pkg.meta.name.clone(), pkg);
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();

    drop(guard);
    save_database()?;

    Ok(())
}

pub fn unregister_package(name: &str) -> NpkgResult<InstalledPackage> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let pkg = db.packages.remove(name)
        .ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;

    for file in &pkg.files {
        db.file_owners.remove(file);
    }

    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();

    drop(guard);
    save_database()?;

    Ok(pkg)
}

pub fn query_installed() -> Vec<InstalledPackage> {
    let guard = DATABASE.read();
    guard.as_ref()
        .map(|db| db.packages.values().cloned().collect())
        .unwrap_or_default()
}

pub fn query_by_name(name: &str) -> Option<InstalledPackage> {
    let guard = DATABASE.read();
    guard.as_ref()
        .and_then(|db| db.packages.get(name).cloned())
}

pub fn query_by_file(path: &str) -> Option<String> {
    let guard = DATABASE.read();
    guard.as_ref()
        .and_then(|db| db.file_owners.get(path).cloned())
}

pub fn is_installed(name: &str) -> bool {
    let guard = DATABASE.read();
    guard.as_ref()
        .map(|db| db.packages.contains_key(name))
        .unwrap_or(false)
}

pub fn get_installed_version(name: &str) -> Option<PackageVersion> {
    let guard = DATABASE.read();
    guard.as_ref()
        .and_then(|db| db.packages.get(name))
        .map(|pkg| pkg.meta.version.clone())
}

pub fn get_database_stats() -> Option<DatabaseStats> {
    let guard = DATABASE.read();
    guard.as_ref().map(|db| db.stats.clone())
}

pub fn mark_explicit(name: &str) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let pkg = db.packages.get_mut(name)
        .ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;

    pkg.install_reason = InstallReason::Explicit;
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();

    drop(guard);
    save_database()
}

pub fn mark_dependency(name: &str) -> NpkgResult<()> {
    let mut guard = DATABASE.write();
    let db = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let pkg = db.packages.get_mut(name)
        .ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;

    pkg.install_reason = InstallReason::Dependency;
    db.dirty.store(true, Ordering::SeqCst);
    db.recalculate_stats();

    drop(guard);
    save_database()
}

pub fn get_orphans() -> Vec<String> {
    let guard = DATABASE.read();
    let db = match guard.as_ref() {
        Some(db) => db,
        None => return Vec::new(),
    };

    let mut required: alloc::collections::BTreeSet<String> = alloc::collections::BTreeSet::new();

    for pkg in db.packages.values() {
        if pkg.install_reason == InstallReason::Explicit {
            collect_dependencies(db, &pkg.meta.name, &mut required);
        }
    }

    db.packages.keys()
        .filter(|name| !required.contains(*name))
        .filter(|name| {
            db.packages.get(*name)
                .map(|p| p.install_reason != InstallReason::Explicit)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

fn collect_dependencies(
    db: &PackageDatabase,
    name: &str,
    required: &mut alloc::collections::BTreeSet<String>,
) {
    if required.contains(name) {
        return;
    }

    required.insert(String::from(name));

    if let Some(pkg) = db.packages.get(name) {
        if let Some(deps) = get_package_dependencies(&pkg.meta.name) {
            for dep in deps {
                collect_dependencies(db, &dep, required);
            }
        }
    }
}

fn get_package_dependencies(name: &str) -> Option<Vec<String>> {
    if let Some(manifest) = super::manifest::get_cached_manifest(name) {
        Some(manifest.dependencies.iter().map(|d| d.name.clone()).collect())
    } else {
        None
    }
}

pub fn verify_database_integrity() -> NpkgResult<Vec<String>> {
    let guard = DATABASE.read();
    let db = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let mut issues = Vec::new();

    for (name, pkg) in &db.packages {
        for file in &pkg.files {
            if !file_exists(file) {
                issues.push(alloc::format!("{}: missing file {}", name, file));
            }
        }
    }

    for (file, owner) in &db.file_owners {
        if !db.packages.contains_key(owner) {
            issues.push(alloc::format!("orphan file entry: {} -> {}", file, owner));
        }
    }

    Ok(issues)
}

fn file_exists(path: &str) -> bool {
    crate::fs::vfs::get_vfs()
        .map(|vfs| vfs.exists(path))
        .unwrap_or(false)
}
