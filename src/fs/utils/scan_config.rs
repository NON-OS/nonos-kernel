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

use alloc::{format, string::String, string::ToString, vec::Vec};
use core::sync::atomic::Ordering;

use super::classify::classify_file_by_path;
use super::error::{UtilsError, UtilsResult};
use super::helpers::is_hidden;
use super::scan_stats::{sensitivity_to_value, SCAN_OPERATIONS};
use super::types::{ScanConfig, ScanResult, SensitivityLevel};
use crate::fs::path::normalize_path;
use crate::fs::ramfs::NONOS_FILESYSTEM;

pub fn scan_with_config(dir_path: &str, config: &ScanConfig) -> UtilsResult<Vec<ScanResult>> {
    if dir_path.is_empty() {
        return Err(UtilsError::InvalidPath);
    }

    if dir_path.contains("..") {
        return Err(UtilsError::PathTraversal);
    }

    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut results = Vec::new();
    let mut files_processed = 0usize;

    for path in all_files {
        if files_processed >= config.max_files {
            break;
        }

        if !prefix.is_empty() && !path.starts_with(&prefix) {
            continue;
        }

        let relative_path = if prefix.is_empty() {
            path.clone()
        } else {
            path[prefix.len()..].to_string()
        };

        let depth = relative_path.matches('/').count();
        if depth > config.max_depth {
            continue;
        }

        let is_hidden_file = is_hidden(&path);
        if !config.include_hidden && is_hidden_file {
            continue;
        }

        if !config.extensions.is_empty() {
            let has_matching_ext = config.extensions.iter().any(|ext| {
                path.ends_with(&format!(".{}", ext))
            });
            if !has_matching_ext {
                continue;
            }
        }

        if !config.name_patterns.is_empty() {
            let matches_pattern = config.name_patterns.iter().any(|pattern| {
                path.contains(pattern)
            });
            if !matches_pattern {
                continue;
            }
        }

        let classification = classify_file_by_path(&path);

        if config.sensitivity_threshold != SensitivityLevel::None {
            let threshold_value = sensitivity_to_value(config.sensitivity_threshold);
            let file_value = sensitivity_to_value(classification.sensitivity);
            if file_value < threshold_value {
                continue;
            }
        }

        let size = NONOS_FILESYSTEM
            .get_file_info(&path)
            .map(|info| info.size)
            .unwrap_or(0);

        results.push(ScanResult::new(path, classification, size, depth));
        files_processed += 1;
    }

    results.sort_by(|a, b| a.path.cmp(&b.path));
    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    Ok(results)
}
