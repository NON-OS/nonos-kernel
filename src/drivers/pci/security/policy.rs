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

use spin::Mutex;

pub struct SecurityPolicy {
    pub allow_rom_writes: bool,
    pub allow_arbitrary_bus_master: bool,
    pub allow_interrupt_line_writes: bool,
    pub log_all_config_writes: bool,
    pub enforce_allowlist: bool,
    pub block_unknown_vendors: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_rom_writes: false,
            allow_arbitrary_bus_master: false,
            allow_interrupt_line_writes: true,
            log_all_config_writes: true,
            enforce_allowlist: false,
            block_unknown_vendors: false,
        }
    }
}

pub(super) static POLICY: Mutex<SecurityPolicy> = Mutex::new(SecurityPolicy {
    allow_rom_writes: false,
    allow_arbitrary_bus_master: false,
    allow_interrupt_line_writes: true,
    log_all_config_writes: true,
    enforce_allowlist: false,
    block_unknown_vendors: false,
});

pub fn set_security_policy(policy: SecurityPolicy) {
    *POLICY.lock() = policy;
}

pub fn get_security_policy() -> SecurityPolicy {
    let p = POLICY.lock();
    SecurityPolicy {
        allow_rom_writes: p.allow_rom_writes,
        allow_arbitrary_bus_master: p.allow_arbitrary_bus_master,
        allow_interrupt_line_writes: p.allow_interrupt_line_writes,
        log_all_config_writes: p.log_all_config_writes,
        enforce_allowlist: p.enforce_allowlist,
        block_unknown_vendors: p.block_unknown_vendors,
    }
}
