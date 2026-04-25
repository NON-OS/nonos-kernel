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

use super::config::SandboxConfig;
use super::fs_ops::{create_sandboxed_dir, create_sandboxed_file, create_sandboxed_symlink};
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::Package;
use alloc::string::String;
use alloc::vec::Vec;

pub struct SandboxedInstall {
    pub(super) config: SandboxConfig,
    pub(super) installed_files: Vec<String>,
    pub(super) violated_paths: Vec<String>,
    pub(super) memory_used: u64,
    pub(super) files_created: u32,
    pub(super) start_time: u64,
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
            return Err(NpkgError::SandboxViolation(alloc::format!("path not allowed: {}", path)));
        }
        Ok(())
    }
    pub fn check_memory(&mut self, size: u64) -> NpkgResult<()> {
        if self.memory_used + size > self.config.max_memory {
            return Err(NpkgError::SandboxViolation(String::from("memory limit exceeded")));
        }
        self.memory_used += size;
        Ok(())
    }
    pub fn check_file_count(&mut self) -> NpkgResult<()> {
        if self.files_created >= self.config.max_files {
            return Err(NpkgError::SandboxViolation(String::from("file count limit exceeded")));
        }
        self.files_created += 1;
        Ok(())
    }
    pub fn check_timeout(&self) -> NpkgResult<()> {
        let elapsed = crate::time::unix_timestamp() - self.start_time;
        if elapsed > self.config.timeout_seconds {
            return Err(NpkgError::SandboxViolation(String::from("timeout exceeded")));
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

pub fn install_sandboxed(pkg: &Package, config: SandboxConfig) -> NpkgResult<Vec<String>> {
    let archive_path = crate::npkg::download::download_package(pkg)?;
    let archive_data = crate::fs::read_file_bytes(&archive_path)
        .map_err(|_| NpkgError::IoError(String::from("failed to read archive")))?;
    let archive = crate::npkg::extract::PackageArchive::open(&archive_data)?;
    let mut sandbox = SandboxedInstall::new(config);
    for entry_result in archive.entries() {
        sandbox.check_timeout()?;
        let entry = entry_result?;
        sandbox.check_path(&entry.path)?;
        sandbox.check_file_count()?;
        sandbox.check_memory(entry.size)?;
        let full_path = if entry.path.starts_with('/') {
            entry.path.clone()
        } else {
            alloc::format!("/{}", entry.path)
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
