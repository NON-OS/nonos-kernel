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

use super::classify::classify_file_by_path;
use super::helpers::{get_extension, is_hidden};
use super::matchers::matches_sensitive_pattern;
use super::types::{FileCategory, SensitivityLevel};

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
