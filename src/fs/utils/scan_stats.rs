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

use alloc::{format, string::String};
use core::sync::atomic::{AtomicU64, Ordering};

use super::classify::classify_file_by_path;
use super::helpers::is_hidden;
use super::matchers::matches_sensitive_pattern;
use super::types::{ScanStatistics, SensitivityLevel};
use crate::fs::path::normalize_path;
use crate::fs::ramfs::NONOS_FILESYSTEM;

pub static SCAN_OPERATIONS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn sensitivity_to_value(level: SensitivityLevel) -> u8 {
    match level {
        SensitivityLevel::None => 0,
        SensitivityLevel::Low => 1,
        SensitivityLevel::Medium => 2,
        SensitivityLevel::High => 3,
        SensitivityLevel::Critical => 4,
    }
}

pub fn count_files_by_sensitivity(dir_path: &str) -> [(SensitivityLevel, usize); 5] {
    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut counts = [
        (SensitivityLevel::None, 0usize),
        (SensitivityLevel::Low, 0usize),
        (SensitivityLevel::Medium, 0usize),
        (SensitivityLevel::High, 0usize),
        (SensitivityLevel::Critical, 0usize),
    ];

    for path in all_files {
        if !prefix.is_empty() && !path.starts_with(&prefix) {
            continue;
        }

        let classification = classify_file_by_path(&path);
        match classification.sensitivity {
            SensitivityLevel::None => counts[0].1 += 1,
            SensitivityLevel::Low => counts[1].1 += 1,
            SensitivityLevel::Medium => counts[2].1 += 1,
            SensitivityLevel::High => counts[3].1 += 1,
            SensitivityLevel::Critical => counts[4].1 += 1,
        }
    }

    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    counts
}

pub fn get_scan_statistics() -> ScanStatistics {
    let all_files = NONOS_FILESYSTEM.list_files();
    let mut stats = ScanStatistics::default();

    for path in &all_files {
        stats.files_scanned += 1;

        if is_hidden(path) {
            stats.hidden_files += 1;
        }

        if matches_sensitive_pattern(path) {
            stats.sensitive_files += 1;
        }

        if let Ok(info) = NONOS_FILESYSTEM.get_file_info(path) {
            stats.bytes_scanned += info.size as u64;
        }

        let depth = path.matches('/').count();
        if depth > stats.max_depth_reached {
            stats.max_depth_reached = depth;
        }
    }

    stats
}

pub fn get_scan_operation_count() -> u64 {
    SCAN_OPERATIONS.load(Ordering::Relaxed)
}
