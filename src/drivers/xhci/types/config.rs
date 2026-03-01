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

use crate::drivers::xhci::constants::{DEFAULT_TIMEOUT_SPINS, MAX_ENUMERATION_ATTEMPTS};

#[derive(Clone, Copy, Debug)]
pub struct XhciConfig {
    pub command_timeout_spins: u32,
    pub transfer_timeout_spins: u32,
    pub enable_enumeration_rate_limit: bool,
    pub max_enumeration_attempts: u32,
    pub security_logging: bool,
}

impl Default for XhciConfig {
    fn default() -> Self {
        Self {
            command_timeout_spins: DEFAULT_TIMEOUT_SPINS,
            transfer_timeout_spins: DEFAULT_TIMEOUT_SPINS,
            enable_enumeration_rate_limit: true,
            max_enumeration_attempts: MAX_ENUMERATION_ATTEMPTS,
            security_logging: true,
        }
    }
}
