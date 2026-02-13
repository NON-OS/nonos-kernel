// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;

use super::global::{init_global_state, shutdown_global_state};
use super::storage::{disable_boot_log, enable_boot_log};

pub fn init_logging(st: &mut SystemTable<Boot>) {
    init_global_state(st);
    enable_boot_log();
}

pub fn shutdown_logging() {
    disable_boot_log();
    shutdown_global_state();
}
