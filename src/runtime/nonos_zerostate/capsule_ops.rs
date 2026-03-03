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

use alloc::{string::String, sync::Arc, vec::Vec};

use crate::runtime::nonos_capsule::{Capsule, CapsuleQuotas};
use crate::runtime::nonos_isolation::{IsolationPolicy, IsolationState};
use crate::syscall::capabilities::CapabilityToken;

use super::registry::get_registry;

pub fn register_capsule(
    name: &'static str,
    peers: Vec<&'static str>,
    quotas: CapsuleQuotas,
) -> Arc<Capsule> {
    let cap = Capsule::new(name, peers, quotas.clone());
    let policy = IsolationPolicy {
        inbox_capacity: quotas.inbox_capacity,
        max_msg_bytes: quotas.max_msg_bytes,
        max_bytes_per_sec: quotas.max_bytes_per_sec,
        heartbeat_interval_ms: quotas.heartbeat_interval_ms,
    };
    let iso = IsolationState::new(name, policy);

    {
        let mut reg = get_registry().write();
        reg.by_name.insert(String::from(name), cap.id.get());
        reg.iso.insert(cap.id.get(), iso);
        reg.by_id.insert(cap.id.get(), Arc::clone(&cap));
    }

    crate::drivers::console::write_message(
        &alloc::format!("zerostate: registered capsule '{}' id={}", name, cap.id.get())
    );

    cap
}

pub fn start_capsule(name: &str, token: &CapabilityToken) -> Result<(), &'static str> {
    let cap = get_capsule_by_name(name).ok_or("capsule not found")?;
    cap.start(token)
}

pub fn stop_capsule(name: &str) -> Result<(), &'static str> {
    let cap = get_capsule_by_name(name).ok_or("capsule not found")?;
    cap.stop();
    Ok(())
}

pub fn get_capsule_by_name(name: &str) -> Option<Arc<Capsule>> {
    let reg = get_registry().read();
    let id = reg.by_name.get(name)?;
    reg.by_id.get(id).cloned()
}
