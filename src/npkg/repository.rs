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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use super::types::{Package, PackageVersion, Architecture};
use super::manifest::parse_manifest;
use super::signature::{verify_package, PackageSignature};
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryKind {
    Official,
    Community,
    ThirdParty,
    Local,
}

impl RepositoryKind {
    pub fn trust_level(&self) -> u8 {
        match self {
            Self::Official => 100,
            Self::Community => 75,
            Self::ThirdParty => 50,
            Self::Local => 25,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepositoryConfig {
    pub name: String,
    pub url: String,
    pub kind: RepositoryKind,
    pub enabled: bool,
    pub signature_required: bool,
    pub priority: u32,
}

impl RepositoryConfig {
    pub fn official(name: &str, url: &str) -> Self {
        Self {
            name: String::from(name),
            url: String::from(url),
            kind: RepositoryKind::Official,
            enabled: true,
            signature_required: true,
            priority: 100,
        }
    }

    pub fn community(name: &str, url: &str) -> Self {
        Self {
            name: String::from(name),
            url: String::from(url),
            kind: RepositoryKind::Community,
            enabled: true,
            signature_required: true,
            priority: 50,
        }
    }

    pub fn local(path: &str) -> Self {
        Self {
            name: String::from("local"),
            url: String::from(path),
            kind: RepositoryKind::Local,
            enabled: true,
            signature_required: false,
            priority: 200,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Repository {
    pub config: RepositoryConfig,
    pub packages: BTreeMap<String, Vec<Package>>,
    pub last_sync: u64,
    pub package_count: usize,
}

impl Repository {
    pub fn new(config: RepositoryConfig) -> Self {
        Self {
            config,
            packages: BTreeMap::new(),
            last_sync: 0,
            package_count: 0,
        }
    }

    pub fn find_package(&self, name: &str) -> Option<&Package> {
        self.packages.get(name).and_then(|versions| {
            versions.iter().max_by(|a, b| a.meta.version.cmp(&b.meta.version))
        })
    }

    pub fn find_package_version(&self, name: &str, version: &PackageVersion) -> Option<&Package> {
        self.packages.get(name).and_then(|versions| {
            versions.iter().find(|p| &p.meta.version == version)
        })
    }

    pub fn list_versions(&self, name: &str) -> Vec<&PackageVersion> {
        self.packages.get(name)
            .map(|versions| versions.iter().map(|p| &p.meta.version).collect())
            .unwrap_or_default()
    }

    pub fn search(&self, query: &str) -> Vec<&Package> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for versions in self.packages.values() {
            if let Some(pkg) = versions.iter().max_by(|a, b| a.meta.version.cmp(&b.meta.version)) {
                if pkg.meta.name.to_lowercase().contains(&query_lower)
                    || pkg.meta.description.to_lowercase().contains(&query_lower)
                {
                    results.push(pkg);
                }
            }
        }

        results
    }
}

pub struct RepositoryManager {
    repositories: Vec<Repository>,
    sync_in_progress: AtomicBool,
    total_packages: AtomicU64,
}

impl RepositoryManager {
    fn new() -> Self {
        Self {
            repositories: Vec::new(),
            sync_in_progress: AtomicBool::new(false),
            total_packages: AtomicU64::new(0),
        }
    }
}

static REPO_MANAGER: RwLock<Option<RepositoryManager>> = RwLock::new(None);

pub fn init_repository_manager() -> NpkgResult<()> {
    let mut manager = REPO_MANAGER.write();
    if manager.is_some() {
        return Ok(());
    }

    let mut rm = RepositoryManager::new();

    rm.repositories.push(Repository::new(RepositoryConfig::official(
        "core",
        "https://repo.nonos.dev/core",
    )));

    rm.repositories.push(Repository::new(RepositoryConfig::official(
        "extra",
        "https://repo.nonos.dev/extra",
    )));

    rm.repositories.push(Repository::new(RepositoryConfig::community(
        "community",
        "https://repo.nonos.dev/community",
    )));

    load_custom_repositories(&mut rm)?;

    *manager = Some(rm);
    Ok(())
}

fn load_custom_repositories(manager: &mut RepositoryManager) -> NpkgResult<()> {
    let config_path = "/etc/npkg/repositories.conf";

    let content_bytes = match crate::fs::read_file(config_path) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    let content = core::str::from_utf8(&content_bytes).unwrap_or("");

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(config) = parse_repo_line(line) {
            if !manager.repositories.iter().any(|r| r.config.name == config.name) {
                manager.repositories.push(Repository::new(config));
            }
        }
    }

    Ok(())
}

fn parse_repo_line(line: &str) -> Option<RepositoryConfig> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let name = String::from(parts[0]);
    let url = String::from(parts[1]);

    let mut kind = RepositoryKind::ThirdParty;
    let mut enabled = true;
    let mut sig_required = true;
    let mut priority = 25u32;

    for part in parts.iter().skip(2) {
        if *part == "disabled" {
            enabled = false;
        } else if *part == "nosig" {
            sig_required = false;
        } else if *part == "official" {
            kind = RepositoryKind::Official;
            priority = 100;
        } else if *part == "community" {
            kind = RepositoryKind::Community;
            priority = 50;
        } else if let Some(p) = part.strip_prefix("priority=") {
            if let Ok(v) = p.parse() {
                priority = v;
            }
        }
    }

    Some(RepositoryConfig {
        name,
        url,
        kind,
        enabled,
        signature_required: sig_required,
        priority,
    })
}

pub fn get_repository_manager() -> Option<&'static RwLock<Option<RepositoryManager>>> {
    Some(&REPO_MANAGER)
}

pub fn add_repository(config: RepositoryConfig) -> NpkgResult<()> {
    let mut guard = REPO_MANAGER.write();
    let manager = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    if manager.repositories.iter().any(|r| r.config.name == config.name) {
        return Err(NpkgError::InternalError(alloc::format!("repository {} exists", config.name)));
    }

    manager.repositories.push(Repository::new(config));
    save_repositories()?;
    Ok(())
}

pub fn remove_repository(name: &str) -> NpkgResult<()> {
    let mut guard = REPO_MANAGER.write();
    let manager = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let initial_len = manager.repositories.len();
    manager.repositories.retain(|r| r.config.name != name);

    if manager.repositories.len() == initial_len {
        return Err(NpkgError::RepositoryNotFound(String::from(name)));
    }

    save_repositories()?;
    Ok(())
}

pub fn list_repositories() -> Vec<RepositoryConfig> {
    let guard = REPO_MANAGER.read();
    guard.as_ref()
        .map(|m| m.repositories.iter().map(|r| r.config.clone()).collect())
        .unwrap_or_default()
}

fn save_repositories() -> NpkgResult<()> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let mut content = String::new();
    content.push_str("# NONOS Package Manager Repository Configuration\n\n");

    for repo in &manager.repositories {
        let cfg = &repo.config;
        if cfg.kind == RepositoryKind::Official || cfg.kind == RepositoryKind::Community {
            continue;
        }

        content.push_str(&cfg.name);
        content.push(' ');
        content.push_str(&cfg.url);

        if !cfg.enabled {
            content.push_str(" disabled");
        }
        if !cfg.signature_required {
            content.push_str(" nosig");
        }
        content.push_str(&alloc::format!(" priority={}", cfg.priority));
        content.push('\n');
    }

    let _ = crate::fs::mkdir("/etc/npkg", 0o755);
    crate::fs::nonos_vfs::vfs_write_file("/etc/npkg/repositories.conf", content.as_bytes())
        .map_err(|_| NpkgError::IoError(String::from("failed to save config")))?;

    Ok(())
}

pub fn sync_repository(name: &str) -> NpkgResult<usize> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    if manager.sync_in_progress.swap(true, Ordering::SeqCst) {
        return Err(NpkgError::InternalError(String::from("sync already in progress")));
    }

    drop(guard);

    let result = sync_repository_internal(name);

    let guard = REPO_MANAGER.read();
    if let Some(m) = guard.as_ref() {
        m.sync_in_progress.store(false, Ordering::SeqCst);
    }

    result
}

fn sync_repository_internal(name: &str) -> NpkgResult<usize> {
    let mut guard = REPO_MANAGER.write();
    let manager = guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;

    let repo = manager.repositories.iter_mut()
        .find(|r| r.config.name == name)
        .ok_or_else(|| NpkgError::RepositoryNotFound(String::from(name)))?;

    if !repo.config.enabled {
        return Ok(0);
    }

    let url = &repo.config.url;

    if url.starts_with('/') || url.starts_with("file://") {
        return sync_local_repository(repo);
    }

    let index_url = alloc::format!("{}/index.npkg", url);
    let sig_url = alloc::format!("{}/index.npkg.sig", url);

    let index_data = download_url(&index_url)?;

    if repo.config.signature_required {
        let sig_data = download_url(&sig_url)?;
        let signature = PackageSignature::from_bytes(&sig_data)
            .ok_or_else(|| NpkgError::SignatureInvalid(String::from("malformed")))?;
        verify_package(&index_data, &signature)?;
    }

    let count = parse_repository_index(repo, &index_data)?;
    repo.last_sync = crate::time::unix_timestamp();
    repo.package_count = count;

    Ok(count)
}

fn sync_local_repository(repo: &mut Repository) -> NpkgResult<usize> {
    let path = repo.config.url.strip_prefix("file://").unwrap_or(&repo.config.url);
    let index_path = alloc::format!("{}/index.npkg", path);

    let index_data = crate::fs::read_file_bytes(&index_path)
        .map_err(|_| NpkgError::RepositorySyncFailed(String::from("index not found")))?;

    let count = parse_repository_index(repo, &index_data)?;
    repo.last_sync = crate::time::unix_timestamp();
    repo.package_count = count;

    Ok(count)
}

fn download_url(url: &str) -> NpkgResult<Vec<u8>> {
    if !crate::network::is_network_available() {
        return Err(NpkgError::NetworkUnavailable);
    }

    crate::network::http_client::fetch(url)
        .map_err(|_| NpkgError::DownloadFailed(String::from(url)))
}

fn parse_repository_index(repo: &mut Repository, data: &[u8]) -> NpkgResult<usize> {
    let text = core::str::from_utf8(data)
        .map_err(|_| NpkgError::ManifestParseError(String::from("invalid UTF-8")))?;

    repo.packages.clear();
    let mut count = 0;

    let mut current_manifest = Vec::new();
    let mut in_package = false;

    for line in text.lines() {
        if line.starts_with("---") {
            if in_package && !current_manifest.is_empty() {
                if let Ok(manifest) = parse_manifest(&current_manifest) {
                    let pkg = manifest.package;
                    let name = pkg.meta.name.clone();
                    repo.packages.entry(name).or_insert_with(Vec::new).push(pkg);
                    count += 1;
                }
                current_manifest.clear();
            }
            in_package = true;
            continue;
        }

        if in_package {
            current_manifest.extend_from_slice(line.as_bytes());
            current_manifest.push(b'\n');
        }
    }

    if in_package && !current_manifest.is_empty() {
        if let Ok(manifest) = parse_manifest(&current_manifest) {
            let pkg = manifest.package;
            let name = pkg.meta.name.clone();
            repo.packages.entry(name).or_insert_with(Vec::new).push(pkg);
            count += 1;
        }
    }

    Ok(count)
}

pub fn sync_all_repositories() -> NpkgResult<usize> {
    let repos: Vec<String> = {
        let guard = REPO_MANAGER.read();
        guard.as_ref()
            .map(|m| m.repositories.iter()
                .filter(|r| r.config.enabled)
                .map(|r| r.config.name.clone())
                .collect())
            .unwrap_or_default()
    };

    let mut total = 0;
    let mut last_error = None;

    for name in repos {
        match sync_repository(&name) {
            Ok(count) => total += count,
            Err(e) => last_error = Some(e),
        }
    }

    if total == 0 {
        if let Some(e) = last_error {
            return Err(e);
        }
    }

    let guard = REPO_MANAGER.read();
    if let Some(m) = guard.as_ref() {
        m.total_packages.store(total as u64, Ordering::SeqCst);
    }

    Ok(total)
}

pub fn find_package(name: &str) -> Option<Package> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;

    let mut best: Option<(&Package, u32)> = None;

    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }

        if let Some(pkg) = repo.find_package(name) {
            let priority = repo.config.priority;
            match best {
                None => best = Some((pkg, priority)),
                Some((current, cur_pri)) => {
                    if priority > cur_pri || (priority == cur_pri && pkg.meta.version > current.meta.version) {
                        best = Some((pkg, priority));
                    }
                }
            }
        }
    }

    best.map(|(p, _)| p.clone())
}

pub fn find_package_version(name: &str, version: &PackageVersion) -> Option<Package> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;

    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }

        if let Some(pkg) = repo.find_package_version(name, version) {
            return Some(pkg.clone());
        }
    }

    None
}

pub fn search_packages(query: &str) -> Vec<Package> {
    let guard = REPO_MANAGER.read();
    let manager = match guard.as_ref() {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut results: BTreeMap<String, Package> = BTreeMap::new();

    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }

        for pkg in repo.search(query) {
            let name = &pkg.meta.name;
            if !results.contains_key(name) {
                results.insert(name.clone(), pkg.clone());
            }
        }
    }

    results.into_values().collect()
}

pub fn get_package_url(name: &str, version: &PackageVersion, arch: Architecture) -> Option<String> {
    let guard = REPO_MANAGER.read();
    let manager = guard.as_ref()?;

    for repo in &manager.repositories {
        if !repo.config.enabled {
            continue;
        }

        if repo.find_package_version(name, version).is_some() {
            let filename = alloc::format!("{}-{}-{}.npkg", name, version.to_string(), arch.as_str());
            let url = alloc::format!("{}/packages/{}", repo.config.url, filename);
            return Some(url);
        }
    }

    None
}
