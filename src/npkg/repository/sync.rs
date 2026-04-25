// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::manager::REPO_MANAGER;
use super::repo::Repository;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::manifest::parse_manifest;
use crate::npkg::signature::{verify_package, PackageSignature};
use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::Ordering;

pub fn sync_repository(name: &str) -> NpkgResult<usize> {
    let guard = REPO_MANAGER.read();
    let manager =
        guard.as_ref().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
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
    let manager =
        guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let repo = manager
        .repositories
        .iter_mut()
        .find(|r| r.config.name == name)
        .ok_or_else(|| NpkgError::RepositoryNotFound(String::from(name)))?;
    if !repo.config.enabled {
        return Ok(0);
    }
    let url = &repo.config.url;
    if url.starts_with('/') || url.starts_with("file://") {
        return sync_local_repository(repo);
    }
    let (index_url, sig_url) = (format!("{}/index.npkg", url), format!("{}/index.npkg.sig", url));
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
    let index_data = crate::fs::read_file_bytes(&format!("{}/index.npkg", path))
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
    let (mut count, mut current_manifest, mut in_package) = (0, Vec::new(), false);
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
        guard
            .as_ref()
            .map(|m| {
                m.repositories
                    .iter()
                    .filter(|r| r.config.enabled)
                    .map(|r| r.config.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (mut total, mut last_error) = (0, None);
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
