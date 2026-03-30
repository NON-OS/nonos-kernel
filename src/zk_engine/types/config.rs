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

use alloc::string::String;

#[derive(Debug, Clone)]
pub struct ZKConfig {
    pub max_constraints: usize,
    pub max_witnesses: usize,
    pub enable_preprocessing: bool,
    pub enable_verification_cache: bool,
    pub trusted_setup_path: Option<String>,
}

impl Default for ZKConfig {
    fn default() -> Self {
        Self {
            max_constraints: 1_000_000,
            max_witnesses: 100_000,
            enable_preprocessing: true,
            enable_verification_cache: true,
            trusted_setup_path: None,
        }
    }
}
