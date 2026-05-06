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

//! Shared `--prev-serial` enforcement. Both `sign` and `verify`
//! offer the same monotonic-serial guarantee so a CI step can
//! refuse a downgrade attempt without trusting the file system.

use crate::args::Flags;
use crate::error::CliError;

pub(super) fn enforce_monotonic(current: u64, flags: &Flags) -> Result<(), CliError> {
    let Some(prev_str) = flags.optional("previous-serial") else {
        return Ok(());
    };
    let prev = prev_str
        .parse::<u64>()
        .map_err(|_| CliError::Json(format!("--previous-serial: not a u64: {prev_str}")))?;
    if current <= prev {
        return Err(CliError::SerialRollback { previous: prev, current });
    }
    Ok(())
}
