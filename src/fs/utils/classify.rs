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

use alloc::string::ToString;

use super::helpers::{get_extension, is_hidden};
use super::matchers::{is_credential_file, is_ssh_key, matches_sensitive_pattern};
use super::patterns::*;
use super::types::{FileCategory, FileClassification, SensitivityLevel};

pub fn classify_file_by_path(path: &str) -> FileClassification {
    let lower_path = path.to_lowercase();
    let hidden = is_hidden(path);

    let ext = get_extension(&lower_path);
    let _filename = super::helpers::get_filename(&lower_path);

    if is_ssh_key(&lower_path) {
        return FileClassification {
            category: FileCategory::CryptoKey,
            sensitivity: SensitivityLevel::Critical,
            is_hidden: hidden,
            extension: ext.map(|e| e.to_string()),
        };
    }

    if is_credential_file(&lower_path) {
        return FileClassification {
            category: FileCategory::Credential,
            sensitivity: SensitivityLevel::Critical,
            is_hidden: hidden,
            extension: ext.map(|e| e.to_string()),
        };
    }

    if let Some(ext) = ext {
        if CRYPTO_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::CryptoKey,
                sensitivity: SensitivityLevel::High,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if CERTIFICATE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Certificate,
                sensitivity: SensitivityLevel::Medium,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if DATABASE_EXTENSIONS.contains(&ext) {
            let sensitivity = if matches_sensitive_pattern(path) {
                SensitivityLevel::High
            } else {
                SensitivityLevel::Medium
            };
            return FileClassification {
                category: FileCategory::Database,
                sensitivity,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if CONFIG_EXTENSIONS.contains(&ext) {
            let sensitivity = if matches_sensitive_pattern(path) {
                SensitivityLevel::High
            } else {
                SensitivityLevel::Low
            };
            return FileClassification {
                category: FileCategory::Configuration,
                sensitivity,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if ARCHIVE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Archive,
                sensitivity: SensitivityLevel::Low,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if BACKUP_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Backup,
                sensitivity: SensitivityLevel::Low,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if LOG_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Log,
                sensitivity: SensitivityLevel::Low,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }

        if EXECUTABLE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Executable,
                sensitivity: SensitivityLevel::Medium,
                is_hidden: hidden,
                extension: Some(ext.to_string()),
            };
        }
    }

    if hidden {
        let sensitivity = if matches_sensitive_pattern(path) {
            SensitivityLevel::Medium
        } else {
            SensitivityLevel::Low
        };
        return FileClassification {
            category: FileCategory::Hidden,
            sensitivity,
            is_hidden: true,
            extension: ext.map(|e| e.to_string()),
        };
    }

    FileClassification {
        category: FileCategory::Regular,
        sensitivity: SensitivityLevel::None,
        is_hidden: false,
        extension: ext.map(|e| e.to_string()),
    }
}
