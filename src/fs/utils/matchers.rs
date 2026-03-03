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

use alloc::string::{String, ToString};

use super::helpers::{get_extension, get_filename};
use super::patterns::*;

pub fn matches_sensitive_pattern(path: &str) -> bool {
    let lower_path = path.to_lowercase();

    if let Some(ext) = get_extension(&lower_path) {
        if SENSITIVE_EXTENSIONS.contains(&ext) {
            return true;
        }
    }

    if let Some(name) = get_filename(&lower_path) {
        if SENSITIVE_FILENAMES.iter().any(|&sensitive| name == sensitive || name.ends_with(sensitive)) {
            return true;
        }
    }

    for pattern in SENSITIVE_PATTERNS {
        if lower_path.contains(pattern) {
            return true;
        }
    }

    false
}

pub fn matches_extension(path: &str, extensions: &[&str]) -> bool {
    if let Some(ext) = get_extension(&path.to_lowercase()) {
        extensions.contains(&ext)
    } else {
        false
    }
}

pub fn matches_name_pattern(path: &str, patterns: &[&str]) -> bool {
    let lower_path = path.to_lowercase();
    patterns.iter().any(|pattern| lower_path.contains(pattern))
}

pub fn is_config_file(path: &str) -> bool {
    matches_extension(path, CONFIG_EXTENSIONS)
}

pub fn is_crypto_file(path: &str) -> bool {
    matches_extension(path, CRYPTO_EXTENSIONS)
}

pub fn is_database_file(path: &str) -> bool {
    matches_extension(path, DATABASE_EXTENSIONS)
}

pub fn is_backup_file(path: &str) -> bool {
    matches_extension(path, BACKUP_EXTENSIONS)
}

pub fn is_log_file(path: &str) -> bool {
    matches_extension(path, LOG_EXTENSIONS)
}

pub fn is_executable_file(path: &str) -> bool {
    matches_extension(path, EXECUTABLE_EXTENSIONS)
}

pub fn is_temporary_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".tmp") ||
    lower.ends_with(".temp") ||
    lower.ends_with(".swp") ||
    lower.ends_with("~") ||
    lower.contains("/tmp/") ||
    lower.contains("/temp/")
}

pub fn is_ssh_key(lower_path: &str) -> bool {
    if let Some(name) = get_filename(lower_path) {
        matches!(name,
            "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" |
            "id_rsa.pub" | "id_dsa.pub" | "id_ecdsa.pub" | "id_ed25519.pub" |
            "authorized_keys" | "known_hosts" |
            "ssh_host_rsa_key" | "ssh_host_dsa_key" | "ssh_host_ecdsa_key" | "ssh_host_ed25519_key"
        )
    } else {
        false
    }
}

pub fn is_credential_file(lower_path: &str) -> bool {
    if let Some(name) = get_filename(lower_path) {
        matches!(name,
            ".env" | ".env.local" | ".env.production" | ".env.development" |
            ".htpasswd" | ".netrc" | ".npmrc" | ".pypirc" |
            "shadow" | "passwd" | "master.passwd" |
            "credentials" | "credentials.json" | "secrets" | "secrets.yaml" | "secrets.yml" |
            "service_account.json" | "kubeconfig" |
            "token" | "access_token" | "refresh_token" | "api_key" | "apikey"
        )
    } else {
        false
    }
}

pub fn normalize_path(path: &str) -> String {
    path.to_lowercase().replace("\\", "/").to_string()
}

pub fn get_file_category(path: &str) -> String {
    if is_config_file(path) {
        "config".to_string()
    } else if is_crypto_file(path) {
        "crypto".to_string()
    } else if is_database_file(path) {
        "database".to_string()
    } else if is_executable_file(path) {
        "executable".to_string()
    } else if is_log_file(path) {
        "log".to_string()
    } else {
        "other".to_string()
    }
}
