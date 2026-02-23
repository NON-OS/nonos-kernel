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
use super::types::*;

const SENSITIVE_EXTENSIONS: &[&str] = &[
    "key", "pem", "p12", "pfx", "gpg", "asc", "pgp",
    "crt", "cer", "der", "p7b", "p7c",
    "env", "htpasswd", "netrc", "npmrc",
    "keystore", "jks", "kdbx",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
];

const SENSITIVE_FILENAMES: &[&str] = &[
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
    "shadow", "passwd", "master.passwd",
    "secrets", "credentials", "password", "passwords",
    "token", "access_token", "refresh_token", "api_key",
    "config.json", "secrets.yaml", "secrets.yml",
    "credentials.json", "service_account.json",
    ".env", ".env.local", ".env.production",
    ".htpasswd", ".netrc", ".npmrc", ".pypirc",
    "kubeconfig", "kube.config",
    "private.key", "server.key", "client.key",
    "keyfile", "keyring",
    "wallet.dat", "seed.txt",
];

const SENSITIVE_PATTERNS: &[&str] = &[
    "secret", "private", "credential", "password", "passwd",
    "apikey", "api_key", "api-key",
    "authtoken", "auth_token", "auth-token",
    "accesskey", "access_key", "access-key",
    "privatekey", "private_key", "private-key",
    "encryption", "decrypt",
];

const CRYPTO_EXTENSIONS: &[&str] = &[
    "key", "pem", "p12", "pfx", "gpg", "asc", "pgp",
    "crt", "cer", "der", "p7b", "p7c", "p7s",
    "keystore", "jks", "kdbx", "kdb",
    "aes", "enc", "encrypted",
];

const CERTIFICATE_EXTENSIONS: &[&str] = &[
    "crt", "cer", "der", "pem", "p7b", "p7c", "p7s", "pfx", "p12",
];

const CONFIG_EXTENSIONS: &[&str] = &[
    "json", "yaml", "yml", "toml", "ini", "cfg", "conf", "config",
    "properties", "xml",
];

const DATABASE_EXTENSIONS: &[&str] = &[
    "db", "sqlite", "sqlite3", "mdb", "accdb", "dbf", "sql",
];

const ARCHIVE_EXTENSIONS: &[&str] = &[
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "tbz2",
];

const BACKUP_EXTENSIONS: &[&str] = &[
    "bak", "backup", "old", "orig", "save", "swp", "tmp",
];

const LOG_EXTENSIONS: &[&str] = &[
    "log", "logs", "out", "err", "trace",
];

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "so", "dylib", "bin", "elf", "com", "bat", "sh", "ps1",
];

#[inline]
pub fn is_hidden(path: &str) -> bool {
    if let Some(name) = get_filename(path) {
        name.starts_with('.')
    } else {
        false
    }
}

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

pub fn classify_file_by_path(path: &str) -> FileClassification {
    let lower_path = path.to_lowercase();
    let is_hidden = is_hidden(path);

    let ext = get_extension(&lower_path);
    let _filename = get_filename(&lower_path);

    if is_ssh_key(&lower_path) {
        return FileClassification {
            category: FileCategory::CryptoKey,
            sensitivity: SensitivityLevel::Critical,
            is_hidden,
            extension: ext.map(|e| e.to_string()),
        };
    }

    if is_credential_file(&lower_path) {
        return FileClassification {
            category: FileCategory::Credential,
            sensitivity: SensitivityLevel::Critical,
            is_hidden,
            extension: ext.map(|e| e.to_string()),
        };
    }

    if let Some(ext) = ext {
        if CRYPTO_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::CryptoKey,
                sensitivity: SensitivityLevel::High,
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }

        if CERTIFICATE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Certificate,
                sensitivity: SensitivityLevel::Medium,
                is_hidden,
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
                is_hidden,
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
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }

        if ARCHIVE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Archive,
                sensitivity: SensitivityLevel::Low,
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }

        if BACKUP_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Backup,
                sensitivity: SensitivityLevel::Low,
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }

        if LOG_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Log,
                sensitivity: SensitivityLevel::Low,
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }

        if EXECUTABLE_EXTENSIONS.contains(&ext) {
            return FileClassification {
                category: FileCategory::Executable,
                sensitivity: SensitivityLevel::Medium,
                is_hidden,
                extension: Some(ext.to_string()),
            };
        }
    }

    if is_hidden {
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

fn is_ssh_key(lower_path: &str) -> bool {
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

fn is_credential_file(lower_path: &str) -> bool {
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

#[inline]
fn get_filename(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(pos) => Some(&trimmed[pos + 1..]),
        None => Some(trimmed),
    }
}

#[inline]
fn get_extension(path: &str) -> Option<&str> {
    let name = get_filename(path)?;
    if name.starts_with('.') && !name[1..].contains('.') {
        return None;
    }
    match name.rfind('.') {
        Some(pos) if pos > 0 => Some(&name[pos + 1..]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hidden() {
        assert!(is_hidden(".gitignore"));
        assert!(is_hidden("/home/user/.bashrc"));
        assert!(is_hidden("/path/to/.hidden"));
        assert!(!is_hidden("visible.txt"));
        assert!(!is_hidden("/path/to/file.txt"));
    }

    #[test]
    fn test_matches_sensitive_pattern() {
        assert!(matches_sensitive_pattern("/home/.ssh/id_rsa"));
        assert!(matches_sensitive_pattern("/app/secrets.yaml"));
        assert!(matches_sensitive_pattern("/etc/passwd"));
        assert!(matches_sensitive_pattern("/app/.env"));
        assert!(matches_sensitive_pattern("/keys/server.key"));
        assert!(!matches_sensitive_pattern("/var/log/app.log"));
        assert!(!matches_sensitive_pattern("/home/user/document.txt"));
    }

    #[test]
    fn test_classify_file() {
        let classification = classify_file_by_path("/home/.ssh/id_rsa");
        assert_eq!(classification.category, FileCategory::CryptoKey);
        assert_eq!(classification.sensitivity, SensitivityLevel::Critical);

        let classification = classify_file_by_path("/app/config.json");
        assert_eq!(classification.category, FileCategory::Configuration);

        let classification = classify_file_by_path("/var/log/app.log");
        assert_eq!(classification.category, FileCategory::Log);
    }

    #[test]
    fn test_get_extension() {
        assert_eq!(get_extension("file.txt"), Some("txt"));
        assert_eq!(get_extension("file.tar.gz"), Some("gz"));
        assert_eq!(get_extension(".hidden"), None);
        assert_eq!(get_extension("noext"), None);
    }
}
