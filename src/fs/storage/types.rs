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

pub const DEFAULT_MAX_STORAGE: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_FILES: usize = 65536;
pub const BLOCK_SIZE: usize = 4096;
pub const INODE_SIZE: usize = 256;

pub const WARNING_THRESHOLD_PERCENT: f32 = 80.0;
pub const CRITICAL_THRESHOLD_PERCENT: f32 = 95.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageHealthStatus {
    Healthy,
    Warning,
    Critical,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub available_bytes: usize,
    pub file_count: usize,
    pub directory_count: usize,
    pub block_size: usize,
    pub total_blocks: usize,
    pub used_blocks: usize,
    pub free_blocks: usize,
}

impl StorageStats {
    pub fn usage_percent(&self) -> f32 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f32 / self.total_bytes as f32) * 100.0
    }

    pub fn free_percent(&self) -> f32 {
        100.0 - self.usage_percent()
    }

    pub fn block_usage_percent(&self) -> f32 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        (self.used_blocks as f32 / self.total_blocks as f32) * 100.0
    }
}

impl Default for StorageStats {
    fn default() -> Self {
        Self {
            total_bytes: DEFAULT_MAX_STORAGE,
            used_bytes: 0,
            available_bytes: DEFAULT_MAX_STORAGE,
            file_count: 0,
            directory_count: 0,
            block_size: BLOCK_SIZE,
            total_blocks: DEFAULT_MAX_STORAGE / BLOCK_SIZE,
            used_blocks: 0,
            free_blocks: DEFAULT_MAX_STORAGE / BLOCK_SIZE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemBreakdown {
    pub ramfs_bytes: usize,
    pub ramfs_files: usize,
    pub cryptofs_bytes: usize,
    pub cryptofs_files: usize,
    pub cache_bytes: usize,
    pub metadata_bytes: usize,
}

impl FilesystemBreakdown {
    pub fn total_bytes(&self) -> usize {
        self.ramfs_bytes + self.cryptofs_bytes + self.cache_bytes + self.metadata_bytes
    }

    pub fn total_files(&self) -> usize {
        self.ramfs_files + self.cryptofs_files
    }
}

impl Default for FilesystemBreakdown {
    fn default() -> Self {
        Self {
            ramfs_bytes: 0,
            ramfs_files: 0,
            cryptofs_bytes: 0,
            cryptofs_files: 0,
            cache_bytes: 0,
            metadata_bytes: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageHealth {
    pub status: StorageHealthStatus,
    pub usage_percent: f32,
    pub inode_usage_percent: f32,
    pub fragmentation_percent: f32,
    pub issues: StorageIssues,
}

impl Default for StorageHealth {
    fn default() -> Self {
        Self {
            status: StorageHealthStatus::Unknown,
            usage_percent: 0.0,
            inode_usage_percent: 0.0,
            fragmentation_percent: 0.0,
            issues: StorageIssues::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StorageIssues {
    pub low_space: bool,
    pub low_inodes: bool,
    pub high_fragmentation: bool,
    pub allocation_failures: u64,
    pub io_errors: u64,
}

impl StorageIssues {
    pub fn has_issues(&self) -> bool {
        self.low_space || self.low_inodes || self.high_fragmentation ||
        self.allocation_failures > 0 || self.io_errors > 0
    }

    pub fn issue_count(&self) -> usize {
        let mut count = 0;
        if self.low_space { count += 1; }
        if self.low_inodes { count += 1; }
        if self.high_fragmentation { count += 1; }
        if self.allocation_failures > 0 { count += 1; }
        if self.io_errors > 0 { count += 1; }
        count
    }
}

#[derive(Debug, Clone)]
pub struct InodeStats {
    pub total_inodes: usize,
    pub used_inodes: usize,
    pub free_inodes: usize,
    pub inode_size: usize,
}

impl InodeStats {
    pub fn usage_percent(&self) -> f32 {
        if self.total_inodes == 0 {
            return 0.0;
        }
        (self.used_inodes as f32 / self.total_inodes as f32) * 100.0
    }
}

impl Default for InodeStats {
    fn default() -> Self {
        Self {
            total_inodes: DEFAULT_MAX_FILES,
            used_inodes: 0,
            free_inodes: DEFAULT_MAX_FILES,
            inode_size: INODE_SIZE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageQuota {
    pub soft_limit: usize,
    pub hard_limit: usize,
    pub current_usage: usize,
    pub file_limit: usize,
    pub file_count: usize,
    pub grace_period_secs: u64,
    pub exceeded_at: Option<u64>,
}

impl StorageQuota {
    pub fn is_soft_exceeded(&self) -> bool {
        self.current_usage >= self.soft_limit
    }

    pub fn is_hard_exceeded(&self) -> bool {
        self.current_usage >= self.hard_limit
    }

    pub fn remaining_bytes(&self) -> usize {
        self.hard_limit.saturating_sub(self.current_usage)
    }

    pub fn remaining_files(&self) -> usize {
        self.file_limit.saturating_sub(self.file_count)
    }
}

impl Default for StorageQuota {
    fn default() -> Self {
        Self {
            soft_limit: DEFAULT_MAX_STORAGE * 90 / 100,
            hard_limit: DEFAULT_MAX_STORAGE,
            current_usage: 0,
            file_limit: DEFAULT_MAX_FILES,
            file_count: 0,
            grace_period_secs: 7 * 24 * 60 * 60,
            exceeded_at: None,
        }
    }
}
