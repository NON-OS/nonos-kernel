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

use alloc::{string::String, string::ToString, vec::Vec, format};
use core::sync::atomic::{AtomicU64, Ordering};

use super::error::{UtilsError, UtilsResult};
use super::types::*;
use super::filters::{is_hidden, matches_sensitive_pattern, classify_file_by_path};
use crate::fs::ramfs::NONOS_FILESYSTEM;
use crate::fs::path::normalize_path;

static SCAN_OPERATIONS: AtomicU64 = AtomicU64::new(0);

pub fn scan_hidden_files(dir_path: &str) -> Vec<String> {
    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut hidden_files: Vec<String> = all_files
        .into_iter()
        .filter(|path| {
            if !prefix.is_empty() && !path.starts_with(&prefix) {
                return false;
            }
            is_hidden(path)
        })
        .collect();

    hidden_files.sort();
    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    hidden_files
}

pub fn scan_sensitive_files(dir_path: &str) -> Vec<String> {
    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut sensitive_files: Vec<String> = all_files
        .into_iter()
        .filter(|path| {
            if !prefix.is_empty() && !path.starts_with(&prefix) {
                return false;
            }
            matches_sensitive_pattern(path)
        })
        .collect();

    sensitive_files.sort();
    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    sensitive_files
}

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

pub fn scan_by_extension(dir_path: &str, extensions: &[&str]) -> Vec<String> {
    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut matching_files: Vec<String> = all_files
        .into_iter()
        .filter(|path| {
            if !prefix.is_empty() && !path.starts_with(&prefix) {
                return false;
            }
            extensions.iter().any(|ext| path.ends_with(&format!(".{}", ext)))
        })
        .collect();

    matching_files.sort();
    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    matching_files
}

pub fn scan_by_category(dir_path: &str, category: FileCategory) -> Vec<String> {
    let normalized = normalize_path(dir_path);
    let all_files = NONOS_FILESYSTEM.list_files();

    let prefix = if normalized == "/" {
        String::new()
    } else if normalized.ends_with('/') {
        normalized.clone()
    } else {
        format!("{}/", normalized)
    };

    let mut matching_files: Vec<String> = all_files
        .into_iter()
        .filter(|path| {
            if !prefix.is_empty() && !path.starts_with(&prefix) {
                return false;
            }
            let classification = classify_file_by_path(path);
            classification.category == category
        })
        .collect();

    matching_files.sort();
    SCAN_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    matching_files
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

#[inline]
fn sensitivity_to_value(level: SensitivityLevel) -> u8 {
    match level {
        SensitivityLevel::None => 0,
        SensitivityLevel::Low => 1,
        SensitivityLevel::Medium => 2,
        SensitivityLevel::High => 3,
        SensitivityLevel::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitivity_ordering() {
        assert!(sensitivity_to_value(SensitivityLevel::Critical) > sensitivity_to_value(SensitivityLevel::High));
        assert!(sensitivity_to_value(SensitivityLevel::High) > sensitivity_to_value(SensitivityLevel::Medium));
        assert!(sensitivity_to_value(SensitivityLevel::Medium) > sensitivity_to_value(SensitivityLevel::Low));
        assert!(sensitivity_to_value(SensitivityLevel::Low) > sensitivity_to_value(SensitivityLevel::None));
    }
}
