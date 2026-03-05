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
use super::types::Package;
use super::error::{NpkgError, NpkgResult};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub allow_network: bool,
    pub allow_root_write: bool,
    pub allowed_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub max_memory: u64,
    pub max_files: u32,
    pub timeout_seconds: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_network: false,
            allow_root_write: false,
            allowed_paths: vec![
                String::from("/usr"),
                String::from("/opt"),
                String::from("/etc"),
                String::from("/var"),
            ],
            denied_paths: vec![
                String::from("/boot"),
                String::from("/dev"),
                String::from("/proc"),
                String::from("/sys"),
                String::from("/root"),
            ],
            max_memory: 256 * 1024 * 1024,
            max_files: 10000,
            timeout_seconds: 300,
        }
    }
}

impl SandboxConfig {
    pub fn permissive() -> Self {
        Self {
            allow_network: true,
            allow_root_write: true,
            allowed_paths: vec![String::from("/")],
            denied_paths: Vec::new(),
            max_memory: 1024 * 1024 * 1024,
            max_files: 100000,
            timeout_seconds: 3600,
        }
    }

    pub fn restrictive() -> Self {
        Self {
            allow_network: false,
            allow_root_write: false,
            allowed_paths: vec![
                String::from("/usr/share"),
                String::from("/usr/lib"),
            ],
            denied_paths: vec![
                String::from("/"),
            ],
            max_memory: 64 * 1024 * 1024,
            max_files: 1000,
            timeout_seconds: 60,
        }
    }

    pub fn is_path_allowed(&self, path: &str) -> bool {
        for denied in &self.denied_paths {
            if path.starts_with(denied) {
                return false;
            }
        }

        if self.allowed_paths.is_empty() {
            return true;
        }

        for allowed in &self.allowed_paths {
            if path.starts_with(allowed) {
                return true;
            }
        }

        false
    }
}

pub struct SandboxedInstall {
    config: SandboxConfig,
    installed_files: Vec<String>,
    violated_paths: Vec<String>,
    memory_used: u64,
    files_created: u32,
    start_time: u64,
}

impl SandboxedInstall {
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            installed_files: Vec::new(),
            violated_paths: Vec::new(),
            memory_used: 0,
            files_created: 0,
            start_time: crate::time::unix_timestamp(),
        }
    }

    pub fn check_path(&mut self, path: &str) -> NpkgResult<()> {
        if !self.config.is_path_allowed(path) {
            self.violated_paths.push(String::from(path));
            return Err(NpkgError::SandboxViolation(alloc::format!(
                "path not allowed: {}",
                path
            )));
        }

        Ok(())
    }

    pub fn check_memory(&mut self, size: u64) -> NpkgResult<()> {
        if self.memory_used + size > self.config.max_memory {
            return Err(NpkgError::SandboxViolation(String::from(
                "memory limit exceeded"
            )));
        }

        self.memory_used += size;
        Ok(())
    }

    pub fn check_file_count(&mut self) -> NpkgResult<()> {
        if self.files_created >= self.config.max_files {
            return Err(NpkgError::SandboxViolation(String::from(
                "file count limit exceeded"
            )));
        }

        self.files_created += 1;
        Ok(())
    }

    pub fn check_timeout(&self) -> NpkgResult<()> {
        let elapsed = crate::time::unix_timestamp() - self.start_time;

        if elapsed > self.config.timeout_seconds {
            return Err(NpkgError::SandboxViolation(String::from(
                "timeout exceeded"
            )));
        }

        Ok(())
    }

    pub fn record_file(&mut self, path: String) {
        self.installed_files.push(path);
    }

    pub fn get_installed_files(&self) -> &[String] {
        &self.installed_files
    }

    pub fn get_violations(&self) -> &[String] {
        &self.violated_paths
    }

    pub fn rollback(&self) -> NpkgResult<()> {
        for file in self.installed_files.iter().rev() {
            if crate::fs::is_directory(file) {
                let _ = crate::fs::rmdir(file);
            } else {
                let _ = crate::fs::unlink(file);
            }
        }

        Ok(())
    }
}

pub fn install_sandboxed(
    pkg: &Package,
    config: SandboxConfig,
) -> NpkgResult<Vec<String>> {
    let archive_path = super::download::download_package(pkg)?;
    let archive_data = crate::fs::read_file_bytes(&archive_path)
        .map_err(|_| NpkgError::IoError(String::from("failed to read archive")))?;

    let archive = super::extract::PackageArchive::open(&archive_data)?;

    let mut sandbox = SandboxedInstall::new(config);

    for entry_result in archive.entries() {
        sandbox.check_timeout()?;

        let entry = entry_result?;
        let path = &entry.path;

        sandbox.check_path(path)?;
        sandbox.check_file_count()?;
        sandbox.check_memory(entry.size)?;

        let full_path = if path.starts_with('/') {
            path.clone()
        } else {
            alloc::format!("/{}", path)
        };

        match entry.entry_type {
            0 => {
                let data = archive.read_file(&entry)?;
                create_sandboxed_file(&full_path, &data, entry.mode)?;
            }
            1 => {
                create_sandboxed_dir(&full_path, entry.mode)?;
            }
            2 => {
                if let Some(ref target) = entry.link_target {
                    create_sandboxed_symlink(&full_path, target)?;
                }
            }
            _ => {}
        }

        sandbox.record_file(full_path);
    }

    Ok(sandbox.installed_files)
}

fn create_sandboxed_file(path: &str, data: &[u8], mode: u32) -> NpkgResult<()> {
    if let Some(parent) = parent_dir(path) {
        ensure_dir_exists(&parent)?;
    }

    crate::fs::nonos_vfs::vfs_write_file(path, data)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("write failed: {}", path)))?;

    let _ = crate::fs::chmod(path, mode);

    Ok(())
}

fn create_sandboxed_dir(path: &str, mode: u32) -> NpkgResult<()> {
    ensure_dir_exists(path)?;
    let _ = crate::fs::chmod(path, mode);
    Ok(())
}

fn create_sandboxed_symlink(path: &str, target: &str) -> NpkgResult<()> {
    if let Some(parent) = parent_dir(path) {
        ensure_dir_exists(&parent)?;
    }

    crate::fs::symlink(target, path)
        .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("symlink failed: {}", path)))?;

    Ok(())
}

fn ensure_dir_exists(path: &str) -> NpkgResult<()> {
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current = String::new();

    for component in components {
        current.push('/');
        current.push_str(component);

        if !dir_exists(&current) {
            crate::fs::mkdir(&current, 0o755)
                .map_err(|_| NpkgError::ExtractionFailed(alloc::format!("mkdir failed: {}", current)))?;
        }
    }

    Ok(())
}

fn dir_exists(path: &str) -> bool {
    crate::fs::is_directory(path)
}

fn parent_dir(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');
    path.rfind('/').map(|idx| {
        if idx == 0 {
            String::from("/")
        } else {
            String::from(&path[..idx])
        }
    })
}

pub fn verify_sandbox_integrity(files: &[String]) -> NpkgResult<Vec<String>> {
    let mut issues = Vec::new();

    for file in files {
        if !file_exists(file) {
            issues.push(alloc::format!("missing: {}", file));
        }
    }

    Ok(issues)
}

fn file_exists(path: &str) -> bool {
    crate::fs::vfs::get_vfs()
        .map(|vfs| vfs.exists(path))
        .unwrap_or(false)
}

pub fn create_isolated_namespace() -> NpkgResult<IsolatedNamespace> {
    Ok(IsolatedNamespace::new())
}

pub struct IsolatedNamespace {
    mount_points: Vec<String>,
}

impl IsolatedNamespace {
    fn new() -> Self {
        Self {
            mount_points: Vec::new(),
        }
    }

    pub fn bind_mount(&mut self, _src: &str, dst: &str) -> NpkgResult<()> {
        self.mount_points.push(String::from(dst));
        Ok(())
    }

    pub fn overlay_mount(&mut self, _lower: &str, _upper: &str, merged: &str) -> NpkgResult<()> {
        self.mount_points.push(String::from(merged));
        Ok(())
    }

    pub fn cleanup(&mut self) -> NpkgResult<()> {
        for mount in self.mount_points.iter().rev() {
            let _ = crate::fs::umount(mount);
        }
        self.mount_points.clear();
        Ok(())
    }
}

impl Drop for IsolatedNamespace {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
