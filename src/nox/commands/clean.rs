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

pub fn cmd_clean(prune_all: bool) -> NoxResult<u64> {
    let msg = if prune_all {
        Output::arrow_yellow("Removing all cached downloads and old versions")
    } else {
        Output::arrow_yellow("Removing old versions")
    };
    crate::drivers::console::write_message(&msg);
    Ok(0)
}
