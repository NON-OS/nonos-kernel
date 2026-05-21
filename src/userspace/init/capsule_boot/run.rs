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

use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;
use crate::services::lifecycle::{self, CapsuleState};
use crate::sys::boot_log;

pub(crate) fn boot(
    prefix: &str,
    name: &'static str,
    spawn_fn: fn() -> Result<(), SpawnError>,
    state_fn: fn() -> &'static CapsuleState,
) {
    match spawn_fn() {
        Ok(()) => {
            boot_log::ok(prefix, "capsule spawned");
            lifecycle::register(lifecycle::Capsule { name, state: state_fn() });
        }
        Err(e) => boot_log::error(super::error::message(prefix, e).as_str()),
    }
}
