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

use crate::capsule::{registry, CapsuleId, CapsuleState};

pub fn cleanup_capsule(id: CapsuleId) {
    cleanup_sandbox(id);
    cleanup_ipc(id);
    cleanup_network(id);
}

fn cleanup_sandbox(id: CapsuleId) {
    if let Some(sb) = registry::get_sandbox_mut(id) {
        sb.terminate(0);
    }
}

fn cleanup_ipc(id: CapsuleId) {
    crate::ipc::capsule::unregister(id);
}

fn cleanup_network(id: CapsuleId) {
    let capsule = match registry::get(id) {
        Some(c) => c,
        None => return,
    };
    if let Some(pid) = capsule.pid {
        crate::network::socket::close_all_for_pid(pid);
    }
}

pub fn cleanup_all_exited() {
    let ids = registry::get_all_ids();
    for id in ids {
        if let Some(c) = registry::get(id) {
            match c.state {
                CapsuleState::Exited(_) | CapsuleState::Faulted => {
                    registry::remove(id);
                }
                _ => {}
            }
        }
    }
}

pub fn force_cleanup(id: CapsuleId) {
    cleanup_capsule(id);
    registry::remove(id);
}
