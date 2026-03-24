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
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct NoxConfig {
    pub prefix: String,
    pub cellar: String,
    pub cache: String,
    pub taps_dir: String,
    pub formula_dir: String,
    pub logs_dir: String,
    pub github_token: Option<String>,
    pub parallel_downloads: usize,
    pub verbose: bool,
    pub force: bool,
    pub no_deps: bool,
    pub build_from_source: bool,
    pub default_taps: Vec<String>,
}

impl Default for NoxConfig {
    fn default() -> Self {
        let mut default_taps = Vec::new();
        default_taps.push(String::from("nonos/core"));
        default_taps.push(String::from("nonos/extra"));
        Self {
            prefix: String::from(super::NOX_PREFIX),
            cellar: String::from(super::NOX_CELLAR),
            cache: String::from(super::NOX_CACHE),
            taps_dir: String::from(super::NOX_TAPS),
            formula_dir: String::from(super::NOX_FORMULAS),
            logs_dir: String::from(super::NOX_LOGS),
            github_token: None,
            parallel_downloads: 4,
            verbose: false,
            force: false,
            no_deps: false,
            build_from_source: false,
            default_taps,
        }
    }
}

impl NoxConfig {
    pub fn with_github_token(mut self, token: String) -> Self {
        self.github_token = Some(token);
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}
