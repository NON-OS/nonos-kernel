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

use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::Ordering;

use super::classify::classify_file_by_path;
use super::helpers::is_hidden;
use super::matchers::matches_sensitive_pattern;
use super::scan_stats::SCAN_OPERATIONS;
use super::types::FileCategory;
use crate::fs::path::normalize_path;
use crate::fs::ramfs::NONOS_FILESYSTEM;

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
