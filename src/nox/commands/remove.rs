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

use crate::nox::output::Output;
use crate::nox::NoxResult;
use alloc::string::String;
use alloc::vec::Vec;

pub struct RemoveOptions {
    pub force: bool,
    pub ignore_dependencies: bool,
    pub zap: bool,
}

impl Default for RemoveOptions {
    fn default() -> Self {
        Self { force: false, ignore_dependencies: false, zap: false }
    }
}

pub fn cmd_remove(formulas: &[&str], _opts: &RemoveOptions) -> NoxResult<Vec<String>> {
    let mut removed = Vec::new();
    for name in formulas {
        let msg = Output::arrow_green(&alloc::format!("Removing {}", name));
        crate::drivers::console::write_message(&msg);
        removed.push(String::from(*name));
    }
    Ok(removed)
}
