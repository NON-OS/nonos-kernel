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

mod error;
mod types;
mod scanner;
mod filters;

pub use error::{UtilsError, UtilsResult};
pub use types::*;
pub use scanner::*;
pub use filters::*;

use alloc::{string::String, vec::Vec};

pub fn list_hidden_files(dir_path: &str) -> Vec<String> {
    scanner::scan_hidden_files(dir_path)
}

pub fn scan_for_sensitive_files(dir_path: &str) -> Vec<String> {
    scanner::scan_sensitive_files(dir_path)
}

pub fn scan_files_with_config(dir_path: &str, config: &ScanConfig) -> UtilsResult<Vec<ScanResult>> {
    scanner::scan_with_config(dir_path, config)
}

pub fn classify_file(path: &str) -> FileClassification {
    filters::classify_file_by_path(path)
}

#[inline]
pub fn is_sensitive_file(path: &str) -> bool {
    filters::matches_sensitive_pattern(path)
}

#[inline]
pub fn is_hidden_file(path: &str) -> bool {
    filters::is_hidden(path)
}
