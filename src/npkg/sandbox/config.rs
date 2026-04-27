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
            allowed_paths: vec![String::from("/usr/share"), String::from("/usr/lib")],
            denied_paths: vec![String::from("/")],
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
