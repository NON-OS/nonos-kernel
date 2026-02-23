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

extern crate alloc;

use alloc::{string::String, vec::Vec};

pub const MAX_SCAN_DEPTH: usize = 64;
pub const MAX_SCAN_FILES: usize = 65536;
pub const MAX_PATTERN_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivityLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Regular,
    Hidden,
    Configuration,
    Credential,
    CryptoKey,
    Certificate,
    Database,
    Executable,
    Archive,
    Temporary,
    Backup,
    Log,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FileClassification {
    pub category: FileCategory,
    pub sensitivity: SensitivityLevel,
    pub is_hidden: bool,
    pub extension: Option<String>,
}

impl FileClassification {
    pub const fn new(category: FileCategory, sensitivity: SensitivityLevel, is_hidden: bool) -> Self {
        Self {
            category,
            sensitivity,
            is_hidden,
            extension: None,
        }
    }

    pub fn with_extension(mut self, ext: String) -> Self {
        self.extension = Some(ext);
        self
    }
}

impl Default for FileClassification {
    fn default() -> Self {
        Self {
            category: FileCategory::Regular,
            sensitivity: SensitivityLevel::None,
            is_hidden: false,
            extension: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub include_hidden: bool,
    pub max_depth: usize,
    pub max_files: usize,
    pub extensions: Vec<String>,
    pub name_patterns: Vec<String>,
    pub sensitivity_threshold: SensitivityLevel,
    pub follow_symlinks: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_hidden: true,
            max_depth: MAX_SCAN_DEPTH,
            max_files: MAX_SCAN_FILES,
            extensions: Vec::new(),
            name_patterns: Vec::new(),
            sensitivity_threshold: SensitivityLevel::None,
            follow_symlinks: false,
        }
    }
}

impl ScanConfig {
    pub const fn new() -> Self {
        Self {
            include_hidden: true,
            max_depth: MAX_SCAN_DEPTH,
            max_files: MAX_SCAN_FILES,
            extensions: Vec::new(),
            name_patterns: Vec::new(),
            sensitivity_threshold: SensitivityLevel::None,
            follow_symlinks: false,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth.min(MAX_SCAN_DEPTH);
        self
    }

    pub fn with_extensions(mut self, exts: Vec<String>) -> Self {
        self.extensions = exts;
        self
    }

    pub fn hidden_only(mut self) -> Self {
        self.include_hidden = true;
        self
    }

    pub fn sensitive_only(mut self, level: SensitivityLevel) -> Self {
        self.sensitivity_threshold = level;
        self
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: String,
    pub classification: FileClassification,
    pub size: usize,
    pub depth: usize,
}

impl ScanResult {
    pub fn new(path: String, classification: FileClassification, size: usize, depth: usize) -> Self {
        Self {
            path,
            classification,
            size,
            depth,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScanStatistics {
    pub files_scanned: u64,
    pub directories_scanned: u64,
    pub hidden_files: u64,
    pub sensitive_files: u64,
    pub bytes_scanned: u64,
    pub max_depth_reached: usize,
    pub errors_encountered: u64,
}
