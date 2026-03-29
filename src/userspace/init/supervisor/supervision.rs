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

use crate::process::core::table::PROCESS_TABLE;
use crate::process::core::types::ProcessState;
use super::super::service_list::CORE_SERVICES;

pub(super) fn supervise_services() {
    for &name in CORE_SERVICES {
        let procs = PROCESS_TABLE.get_all_processes();
        let found = procs.iter().find(|p| *p.name.lock() == name);
        if let Some(pcb) = found {
            let state = *pcb.state.lock();
            if matches!(state, ProcessState::Terminated(_) | ProcessState::Zombie(_)) {
                crate::sys::serial::print(b"[INIT] Service crashed: ");
                crate::sys::serial::println(name.as_bytes());
            }
        }
    }
}
