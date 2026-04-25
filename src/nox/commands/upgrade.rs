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

pub fn cmd_upgrade(formulas: &[&str]) -> NoxResult<Vec<String>> {
    let mut upgraded = Vec::new();
    for name in formulas {
        let msg = Output::arrow_green(&alloc::format!("Upgrading {}", name));
        crate::drivers::console::write_message(&msg);
        upgraded.push(String::from(*name));
    }
    Ok(upgraded)
}

pub fn cmd_upgrade_all() -> NoxResult<Vec<String>> {
    let msg = Output::arrow_blue("Upgrading all outdated formulas");
    crate::drivers::console::write_message(&msg);
    Ok(Vec::new())
}
