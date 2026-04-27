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

use crate::nox::formula::FormulaSpec;
use crate::nox::output::Output;
use crate::nox::NoxResult;
use alloc::string::String;
use alloc::vec::Vec;

pub struct InstallOptions {
    pub force: bool,
    pub verbose: bool,
    pub build_from_source: bool,
    pub ignore_dependencies: bool,
    pub only_dependencies: bool,
    pub fetch_head: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            force: false,
            verbose: false,
            build_from_source: false,
            ignore_dependencies: false,
            only_dependencies: false,
            fetch_head: false,
        }
    }
}

pub fn cmd_install(formulas: &[&str], _opts: &InstallOptions) -> NoxResult<Vec<String>> {
    let mut installed = Vec::new();
    for name in formulas {
        let spec = FormulaSpec::parse(name);
        let msg = Output::arrow_green(&alloc::format!("Installing {}", spec.full_name()));
        crate::drivers::console::write_message(&msg);
        installed.push(spec.name.clone());
    }
    Ok(installed)
}
