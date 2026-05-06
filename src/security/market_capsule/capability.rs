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

//! Caller-side cap gate. The kernel-side client of the marketplace
//! capsule is reachable only by callers holding `CAP_APPS`; the
//! marketplace is the apps-discovery surface. A future installer
//! capsule layers `CAP_PROCESS` on top to actually load a capsule.

use super::error::MarketError;
use crate::services::caps::{has_capability, CAP_APPS};

pub(super) fn gate_call() -> Result<u32, MarketError> {
    let pid = match crate::process::current_pid() {
        Some(p) => p,
        None => return Err(MarketError::NoCallerPid),
    };
    if !has_capability(pid, CAP_APPS) {
        return Err(MarketError::AccessDenied);
    }
    Ok(pid)
}
