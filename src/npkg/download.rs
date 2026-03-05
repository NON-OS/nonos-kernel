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
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use super::types::Package;
use super::repository::get_package_url;
use super::cache::{get_cache_dir, is_cached, get_cached_path};
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub package: String,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub speed_bps: u64,
    pub complete: bool,
}

static CURRENT_DOWNLOAD: AtomicU64 = AtomicU64::new(0);
static TOTAL_DOWNLOAD: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn get_download_progress() -> Option<DownloadProgress> {
    if !DOWNLOAD_ACTIVE.load(Ordering::SeqCst) {
        return None;
    }

    Some(DownloadProgress {
        package: String::new(),
        total_bytes: TOTAL_DOWNLOAD.load(Ordering::SeqCst),
        downloaded_bytes: CURRENT_DOWNLOAD.load(Ordering::SeqCst),
        speed_bps: 0,
        complete: false,
    })
}

pub fn download_package(pkg: &Package) -> NpkgResult<String> {
    let filename = alloc::format!(
        "{}-{}-{}.npkg",
        pkg.meta.name,
        pkg.meta.version.to_string(),
        pkg.meta.architecture.as_str()
    );

    if is_cached(&filename) {
        return get_cached_path(&filename);
    }

    let url = get_package_url(&pkg.meta.name, &pkg.meta.version, pkg.meta.architecture)
        .ok_or_else(|| NpkgError::PackageNotFound(pkg.meta.name.clone()))?;

    download_file(&url, &filename, pkg.meta.size_download)
}

pub fn download_packages(packages: &[&Package]) -> NpkgResult<Vec<String>> {
    let mut paths = Vec::with_capacity(packages.len());

    for pkg in packages {
        let path = download_package(pkg)?;
        paths.push(path);
    }

    Ok(paths)
}

fn download_file(url: &str, filename: &str, expected_size: u64) -> NpkgResult<String> {
    if !crate::network::is_network_available() {
        return Err(NpkgError::NetworkUnavailable);
    }

    DOWNLOAD_ACTIVE.store(true, Ordering::SeqCst);
    CURRENT_DOWNLOAD.store(0, Ordering::SeqCst);
    TOTAL_DOWNLOAD.store(expected_size, Ordering::SeqCst);

    let result = download_file_internal(url, filename);

    DOWNLOAD_ACTIVE.store(false, Ordering::SeqCst);

    result
}

fn download_file_internal(url: &str, filename: &str) -> NpkgResult<String> {
    crate::info!("npkg: downloading {}", filename);

    let data = if url.starts_with("https://") || url.starts_with("http://") {
        download_http(url)?
    } else if let Some(path) = url.strip_prefix("file://") {
        crate::fs::read_file_bytes(path)
            .map_err(|_| NpkgError::DownloadFailed(String::from(url)))?
    } else if url.starts_with('/') {
        crate::fs::read_file_bytes(url)
            .map_err(|_| NpkgError::DownloadFailed(String::from(url)))?
    } else {
        return Err(NpkgError::DownloadFailed(alloc::format!("unsupported URL: {}", url)));
    };

    CURRENT_DOWNLOAD.store(data.len() as u64, Ordering::SeqCst);

    let cache_dir = get_cache_dir();
    let cache_path = alloc::format!("{}/{}", cache_dir, filename);

    let _ = crate::fs::mkdir(&cache_dir, 0o755);

    crate::fs::nonos_vfs::vfs_write_file(&cache_path, &data)
        .map_err(|_| NpkgError::IoError(String::from("failed to cache package")))?;

    crate::info!("npkg: downloaded {} ({} bytes)", filename, data.len());

    Ok(cache_path)
}

fn download_http(url: &str) -> NpkgResult<Vec<u8>> {
    let mut retries = 3;

    loop {
        match crate::network::http_client::fetch(url) {
            Ok(data) => return Ok(data),
            Err(_) => {
                retries -= 1;
                if retries == 0 {
                    return Err(NpkgError::DownloadFailed(String::from(url)));
                }

                for _ in 0..1000000 {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

pub fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = crate::crypto::blake3::blake3_hash(data);
    constant_time_eq(&actual, expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn download_signature(pkg: &Package) -> NpkgResult<Vec<u8>> {
    let filename = alloc::format!(
        "{}-{}-{}.npkg.sig",
        pkg.meta.name,
        pkg.meta.version.to_string(),
        pkg.meta.architecture.as_str()
    );

    crate::log::debug!("npkg: downloading signature {}", filename);

    let url = get_package_url(&pkg.meta.name, &pkg.meta.version, pkg.meta.architecture)
        .map(|u| alloc::format!("{}.sig", u))
        .ok_or_else(|| NpkgError::PackageNotFound(pkg.meta.name.clone()))?;

    if url.starts_with("https://") || url.starts_with("http://") {
        download_http(&url)
    } else if let Some(path) = url.strip_prefix("file://") {
        crate::fs::read_file_bytes(path)
            .map_err(|_| NpkgError::DownloadFailed(url))
    } else {
        crate::fs::read_file_bytes(&url)
            .map_err(|_| NpkgError::DownloadFailed(url))
    }
}

pub fn download_repository_index(repo_url: &str) -> NpkgResult<Vec<u8>> {
    let url = alloc::format!("{}/index.npkg", repo_url);

    if !crate::network::is_network_available() {
        return Err(NpkgError::NetworkUnavailable);
    }

    download_http(&url)
}

pub fn resume_download(url: &str, filename: &str, offset: u64) -> NpkgResult<String> {
    let existing = match crate::fs::read_file_bytes(&alloc::format!("{}/{}.partial", get_cache_dir(), filename)) {
        Ok(data) => data,
        Err(_) => Vec::new(),
    };

    if existing.len() as u64 != offset {
        return download_file(url, filename, 0);
    }

    let remaining = download_http(url)?;

    let mut full_data = existing;
    full_data.extend_from_slice(&remaining);

    let cache_path = alloc::format!("{}/{}", get_cache_dir(), filename);

    crate::fs::nonos_vfs::vfs_write_file(&cache_path, &full_data)
        .map_err(|_| NpkgError::IoError(String::from("failed to save")))?;

    let _ = crate::fs::unlink(&alloc::format!("{}/{}.partial", get_cache_dir(), filename));

    Ok(cache_path)
}
