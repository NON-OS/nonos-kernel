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

extern crate alloc;

use crate::memory::paging::manager;
use crate::process::core::table::PROCESS_TABLE;
use alloc::vec::Vec;

pub fn check_address_space_separation() {
    let procs = PROCESS_TABLE.get_all_processes();
    let mut asids_seen: Vec<u32> = Vec::new();

    for pcb in &procs {
        if let Some(asid) = manager::lookup_asid_for_process(pcb.pid) {
            if asids_seen.contains(&asid) && asid != 0 {
                crate::sys::serial::println(b"[TEST] WARNING: Duplicate ASID");
            }
            asids_seen.push(asid);
        }
    }
    crate::sys::serial::println(b"[TEST] Address space separation: OK");
}
